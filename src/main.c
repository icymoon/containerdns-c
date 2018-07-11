#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_pdump.h>

#include <signal.h>

#include "process.h"
#include "netdev.h"
#include "kdns-adap.h"
#include "dns-conf.h"
#include "util.h"
#include "forward.h"
#include "domain_update.h" 

#define VERSION "0.2.1"
#define DEFAULT_CONF_FILEPATH "/etc/kdns/kdns.cfg"
#define PIDFILE "/var/run/kdns.pid"


static  char *dns_cfgfile;
static  char *dns_procname;

static char *
parse_progname(char *arg) {
    char *p;
    if ((p = strrchr(arg, '/')) != NULL)
        return strdup(p + 1);
    return strdup(arg);
}


static void
parse_args(int argc, char *argv[]) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--conf=", 7) == 0) {
            dns_cfgfile = strdup(argv[i] + 7);
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("Version: %s\n", VERSION);
            exit(0);
        }
        else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: [--conf=%s] [--version] [--help]\n",DEFAULT_CONF_FILEPATH);
            exit(0);
        }else {   
            printf("usage: [--conf=%s] [--version] [--help]\n",DEFAULT_CONF_FILEPATH);
            exit(0);
        }
    }
    if (!dns_cfgfile) {
        dns_cfgfile = strdup(DEFAULT_CONF_FILEPATH);
    }
}


static void signal_handler(int sig)
{
    switch (sig) 
	{
        case SIGQUIT:
            log_msg(LOG_ERR, "QUIT signal @@@.");
            break;
        case SIGTERM:
            log_msg(LOG_ERR, "TERM signal @@@.");
            break;
        case SIGINT:
            log_msg(LOG_ERR, "INT signal @@@.");
            break;
        case SIGHUP:
            log_msg(LOG_ERR, "Program hanged up @@@.");
            break;
        case SIGPIPE:
            log_msg(LOG_ERR, "SIGPIPE @@@.");
            break;
        case SIGCHLD:
            log_msg(LOG_ERR, "SIGCHLD @@@.");
            break;
        case SIGUSR1:
            log_msg(LOG_ERR, "SIGUSR1 @@@.");
            break;
		case SIGUSR2:
			 break;
        case SIGURG:
            log_msg(LOG_ERR, "SIGURG @@@.");
            break;
        default:
            log_msg(LOG_ERR, "Unknown signal(%d) ended program!", sig);
    }
    rte_pdump_uninit();
}


static void init_signals(void)
{
    struct sigaction sigact;
    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGURG, &sigact, NULL);
	sigaction(SIGUSR1, &sigact, NULL);
	sigaction(SIGUSR2, &sigact, NULL);
}


int  main(int argc, char **argv)
{ 
    dns_procname = parse_progname(argv[0]);

    parse_args(argc, argv);
    if (check_pid(PIDFILE) < 0) {
         exit(0);
    }
    write_pid(PIDFILE);
    
    config_file_load(dns_cfgfile,dns_procname);
    
    log_open(g_dns_cfg->comm.log_file);
    
    dns_dpdk_init();
    
    unsigned lcore_id = rte_lcore_id();

    remote_sock_init(g_dns_cfg->comm.fwd_addrs,g_dns_cfg->comm.fwd_def_addrs,g_dns_cfg->comm.fwd_threads);


    netif_queue_core_bind();

   // struct sigaction action;
	/* Setup the signal handling... */
   init_signals();
   rte_pdump_init("/var/run/.dpdk");
    

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {     
        if(kdns_init(lcore_id) < 0){
            log_msg(LOG_ERR, "Error:kdns_init lcore_id =%d\n",lcore_id); 
            exit(-1);
        }
        rte_eal_remote_launch(process_slave, NULL, lcore_id);
    }


    dns_tcp_process_init(g_dns_cfg->netdev.kni_vip);

    process_master(NULL);

    rte_eal_mp_wait_lcore();
    return 0;
}
