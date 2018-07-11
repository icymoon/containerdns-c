/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <string.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_dev.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_reorder.h>

#include "scheduler_pmd_private.h"

/** Configure device */
static int
scheduler_pmd_config(struct rte_cryptodev *dev)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;
	int ret = 0;

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);

		ret = (*slave_dev->dev_ops->dev_configure)(slave_dev);
		if (ret < 0)
			break;
	}

	return ret;
}

static int
update_reorder_buff(struct rte_cryptodev *dev, uint16_t qp_id)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	struct scheduler_qp_ctx *qp_ctx = dev->data->queue_pairs[qp_id];

	if (sched_ctx->reordering_enabled) {
		char reorder_buff_name[RTE_CRYPTODEV_NAME_MAX_LEN];
		uint32_t buff_size = sched_ctx->nb_slaves * PER_SLAVE_BUFF_SIZE;

		if (qp_ctx->reorder_buf) {
			rte_reorder_free(qp_ctx->reorder_buf);
			qp_ctx->reorder_buf = NULL;
		}

		if (!buff_size)
			return 0;

		if (snprintf(reorder_buff_name, RTE_CRYPTODEV_NAME_MAX_LEN,
			"%s_rb_%u_%u", RTE_STR(CRYPTODEV_NAME_SCHEDULER_PMD),
			dev->data->dev_id, qp_id) < 0) {
			CS_LOG_ERR("failed to create unique reorder buffer "
					"name");
			return -ENOMEM;
		}

		qp_ctx->reorder_buf = rte_reorder_create(reorder_buff_name,
				rte_socket_id(), buff_size);
		if (!qp_ctx->reorder_buf) {
			CS_LOG_ERR("failed to create reorder buffer");
			return -ENOMEM;
		}
	} else {
		if (qp_ctx->reorder_buf) {
			rte_reorder_free(qp_ctx->reorder_buf);
			qp_ctx->reorder_buf = NULL;
		}
	}

	return 0;
}

/** Start device */
static int
scheduler_pmd_start(struct rte_cryptodev *dev)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;
	int ret;

	if (dev->data->dev_started)
		return 0;

	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		ret = update_reorder_buff(dev, i);
		if (ret < 0) {
			CS_LOG_ERR("Failed to update reorder buffer");
			return ret;
		}
	}

	if (sched_ctx->mode == CDEV_SCHED_MODE_NOT_SET) {
		CS_LOG_ERR("Scheduler mode is not set");
		return -1;
	}

	if (!sched_ctx->nb_slaves) {
		CS_LOG_ERR("No slave in the scheduler");
		return -1;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*sched_ctx->ops.slave_attach, -ENOTSUP);

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;

		if ((*sched_ctx->ops.slave_attach)(dev, slave_dev_id) < 0) {
			CS_LOG_ERR("Failed to attach slave");
			return -ENOTSUP;
		}
	}

	RTE_FUNC_PTR_OR_ERR_RET(*sched_ctx->ops.scheduler_start, -ENOTSUP);

	if ((*sched_ctx->ops.scheduler_start)(dev) < 0) {
		CS_LOG_ERR("Scheduler start failed");
		return -1;
	}

	/* start all slaves */
	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);

		ret = (*slave_dev->dev_ops->dev_start)(slave_dev);
		if (ret < 0) {
			CS_LOG_ERR("Failed to start slave dev %u",
					slave_dev_id);
			return ret;
		}
	}

	return 0;
}

/** Stop device */
static void
scheduler_pmd_stop(struct rte_cryptodev *dev)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;

	if (!dev->data->dev_started)
		return;

	/* stop all slaves first */
	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);

		(*slave_dev->dev_ops->dev_stop)(slave_dev);
	}

	if (*sched_ctx->ops.scheduler_stop)
		(*sched_ctx->ops.scheduler_stop)(dev);

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;

		if (*sched_ctx->ops.slave_detach)
			(*sched_ctx->ops.slave_detach)(dev, slave_dev_id);
	}
}

/** Close device */
static int
scheduler_pmd_close(struct rte_cryptodev *dev)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;
	int ret;

	/* the dev should be stopped before being closed */
	if (dev->data->dev_started)
		return -EBUSY;

	/* close all slaves first */
	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);

		ret = (*slave_dev->dev_ops->dev_close)(slave_dev);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < dev->data->nb_queue_pairs; i++) {
		struct scheduler_qp_ctx *qp_ctx = dev->data->queue_pairs[i];

		if (qp_ctx->reorder_buf) {
			rte_reorder_free(qp_ctx->reorder_buf);
			qp_ctx->reorder_buf = NULL;
		}

		if (qp_ctx->private_qp_ctx) {
			rte_free(qp_ctx->private_qp_ctx);
			qp_ctx->private_qp_ctx = NULL;
		}
	}

	if (sched_ctx->private_ctx)
		rte_free(sched_ctx->private_ctx);

	if (sched_ctx->capabilities)
		rte_free(sched_ctx->capabilities);

	return 0;
}

/** Get device statistics */
static void
scheduler_pmd_stats_get(struct rte_cryptodev *dev,
	struct rte_cryptodev_stats *stats)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);
		struct rte_cryptodev_stats slave_stats = {0};

		(*slave_dev->dev_ops->stats_get)(slave_dev, &slave_stats);

		stats->enqueued_count += slave_stats.enqueued_count;
		stats->dequeued_count += slave_stats.dequeued_count;

		stats->enqueue_err_count += slave_stats.enqueue_err_count;
		stats->dequeue_err_count += slave_stats.dequeue_err_count;
	}
}

/** Reset device statistics */
static void
scheduler_pmd_stats_reset(struct rte_cryptodev *dev)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t i;

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev *slave_dev =
				rte_cryptodev_pmd_get_dev(slave_dev_id);

		(*slave_dev->dev_ops->stats_reset)(slave_dev);
	}
}

/** Get device info */
static void
scheduler_pmd_info_get(struct rte_cryptodev *dev,
		struct rte_cryptodev_info *dev_info)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	uint32_t max_nb_sessions = sched_ctx->nb_slaves ?
			UINT32_MAX : RTE_CRYPTODEV_VDEV_DEFAULT_MAX_NB_SESSIONS;
	uint32_t i;

	if (!dev_info)
		return;

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		uint8_t slave_dev_id = sched_ctx->slaves[i].dev_id;
		struct rte_cryptodev_info slave_info;

		rte_cryptodev_info_get(slave_dev_id, &slave_info);
		max_nb_sessions = slave_info.sym.max_nb_sessions <
				max_nb_sessions ?
				slave_info.sym.max_nb_sessions :
				max_nb_sessions;
	}

	dev_info->dev_type = dev->dev_type;
	dev_info->feature_flags = dev->feature_flags;
	dev_info->capabilities = sched_ctx->capabilities;
	dev_info->max_nb_queue_pairs = sched_ctx->max_nb_queue_pairs;
	dev_info->sym.max_nb_sessions = max_nb_sessions;
}

/** Release queue pair */
static int
scheduler_pmd_qp_release(struct rte_cryptodev *dev, uint16_t qp_id)
{
	struct scheduler_qp_ctx *qp_ctx = dev->data->queue_pairs[qp_id];

	if (!qp_ctx)
		return 0;

	if (qp_ctx->reorder_buf)
		rte_reorder_free(qp_ctx->reorder_buf);
	if (qp_ctx->private_qp_ctx)
		rte_free(qp_ctx->private_qp_ctx);

	rte_free(qp_ctx);
	dev->data->queue_pairs[qp_id] = NULL;

	return 0;
}

/** Setup a queue pair */
static int
scheduler_pmd_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
	__rte_unused const struct rte_cryptodev_qp_conf *qp_conf, int socket_id)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;
	struct scheduler_qp_ctx *qp_ctx;
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];

	if (snprintf(name, RTE_CRYPTODEV_NAME_MAX_LEN,
			"CRYTO_SCHE PMD %u QP %u",
			dev->data->dev_id, qp_id) < 0) {
		CS_LOG_ERR("Failed to create unique queue pair name");
		return -EFAULT;
	}

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		scheduler_pmd_qp_release(dev, qp_id);

	/* Allocate the queue pair data structure. */
	qp_ctx = rte_zmalloc_socket(name, sizeof(*qp_ctx), RTE_CACHE_LINE_SIZE,
			socket_id);
	if (qp_ctx == NULL)
		return -ENOMEM;

	dev->data->queue_pairs[qp_id] = qp_ctx;

	if (*sched_ctx->ops.config_queue_pair) {
		if ((*sched_ctx->ops.config_queue_pair)(dev, qp_id) < 0) {
			CS_LOG_ERR("Unable to configure queue pair");
			return -1;
		}
	}

	return 0;
}

/** Start queue pair */
static int
scheduler_pmd_qp_start(__rte_unused struct rte_cryptodev *dev,
		__rte_unused uint16_t queue_pair_id)
{
	return -ENOTSUP;
}

/** Stop queue pair */
static int
scheduler_pmd_qp_stop(__rte_unused struct rte_cryptodev *dev,
		__rte_unused uint16_t queue_pair_id)
{
	return -ENOTSUP;
}

/** Return the number of allocated queue pairs */
static uint32_t
scheduler_pmd_qp_count(struct rte_cryptodev *dev)
{
	return dev->data->nb_queue_pairs;
}

static uint32_t
scheduler_pmd_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct scheduler_session);
}

static int
config_slave_sess(struct scheduler_ctx *sched_ctx,
		struct rte_crypto_sym_xform *xform,
		struct scheduler_session *sess,
		uint32_t create)
{
	uint32_t i;

	for (i = 0; i < sched_ctx->nb_slaves; i++) {
		struct scheduler_slave *slave = &sched_ctx->slaves[i];
		struct rte_cryptodev *dev =
				rte_cryptodev_pmd_get_dev(slave->dev_id);

		if (sess->sessions[i]) {
			if (create)
				continue;
			/* !create */
			(*dev->dev_ops->session_clear)(dev,
					(void *)sess->sessions[i]);
			sess->sessions[i] = NULL;
		} else {
			if (!create)
				continue;
			/* create */
			sess->sessions[i] =
					rte_cryptodev_sym_session_create(
							slave->dev_id, xform);
			if (!sess->sessions[i]) {
				config_slave_sess(sched_ctx, NULL, sess, 0);
				return -1;
			}
		}
	}

	return 0;
}

/** Clear the memory of session so it doesn't leave key material behind */
static void
scheduler_pmd_session_clear(struct rte_cryptodev *dev,
	void *sess)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;

	config_slave_sess(sched_ctx, NULL, sess, 0);

	memset(sess, 0, sizeof(struct scheduler_session));
}

static void *
scheduler_pmd_session_configure(struct rte_cryptodev *dev,
	struct rte_crypto_sym_xform *xform, void *sess)
{
	struct scheduler_ctx *sched_ctx = dev->data->dev_private;

	if (config_slave_sess(sched_ctx, xform, sess, 1) < 0) {
		CS_LOG_ERR("unabled to config sym session");
		return NULL;
	}

	return sess;
}

struct rte_cryptodev_ops scheduler_pmd_ops = {
		.dev_configure		= scheduler_pmd_config,
		.dev_start		= scheduler_pmd_start,
		.dev_stop		= scheduler_pmd_stop,
		.dev_close		= scheduler_pmd_close,

		.stats_get		= scheduler_pmd_stats_get,
		.stats_reset		= scheduler_pmd_stats_reset,

		.dev_infos_get		= scheduler_pmd_info_get,

		.queue_pair_setup	= scheduler_pmd_qp_setup,
		.queue_pair_release	= scheduler_pmd_qp_release,
		.queue_pair_start	= scheduler_pmd_qp_start,
		.queue_pair_stop	= scheduler_pmd_qp_stop,
		.queue_pair_count	= scheduler_pmd_qp_count,

		.session_get_size	= scheduler_pmd_session_get_size,
		.session_configure	= scheduler_pmd_session_configure,
		.session_clear		= scheduler_pmd_session_clear,
};

struct rte_cryptodev_ops *rte_crypto_scheduler_pmd_ops = &scheduler_pmd_ops;
