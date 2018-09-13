/*
 * domain_update.c 
 */
#include <jansson.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_ring.h>
#include <rte_rwlock.h>

#include "webserver.h"
#include "db_update.h"
#include "domain_update.h"
#include "util.h"
#include "netdev.h"
#include "view_update.h"



#define DOMAIN_HASH_SIZE  0x3FFFF

#define MSG_RING_SIZE  65536
#define CORE_ID_ERR    0xFF

#define DNS_STATUS_INIT    "init"
#define DNS_STATUS_RUN     "running"

extern struct kdns dpdk_dns[MAX_CORES];
extern int tcp_domian_databd_update(struct domin_info_update* update);


static char * kdns_status = NULL;

static struct web_instance * dins ;
static struct rte_ring *domian_msg_ring[MAX_CORES];


//record all the domain infos,we process it in master core.
static struct domin_info_update *g_domian_hash_list[DOMAIN_HASH_SIZE + 1 ] ;
static int  g_domain_num = 0;
static rte_rwlock_t domian_list_lock;

unsigned master_lcore = CORE_ID_ERR;

static inline unsigned get_master_lcore_id(void){
    if (master_lcore == CORE_ID_ERR)
        master_lcore = rte_get_master_lcore();
    return master_lcore;    
}

static inline struct domin_info_update * msg_copy(struct domin_info_update *src){

    struct domin_info_update * dst = calloc(1,sizeof(struct domin_info_update )) ;
    assert(dst);
    dst->action = src->action;
    dst->ttl    = src->ttl;
    dst->type   = src->type;
    dst->prio    = src->prio;
    dst->weight  = src->weight;
    dst->port    = src->port;
    dst->maxAnswer = src->maxAnswer;
    dst->lb_mode    = src->lb_mode;
    dst->lb_weight  = src->lb_weight;

    memcpy(dst->zone_name,src->zone_name,DB_MAX_NAME_LEN);
    memcpy(dst->view_name,src->view_name,DB_MAX_NAME_LEN);
    memcpy(dst->host,src->host,DB_MAX_NAME_LEN);
    memcpy(dst->domain_name,src->domain_name,DB_MAX_NAME_LEN);
    return dst;  
}

static void domain_info_preprocess(void){
    kdns_status = strdup(DNS_STATUS_INIT);
    int i ;
    for (i=0; i <= DOMAIN_HASH_SIZE; i++){
        g_domian_hash_list[i] = NULL;
    }
    
    rte_rwlock_init(&domian_list_lock);  
}

static unsigned int elfHash(char* str, unsigned int len)  
{  
   unsigned int hash = 0;  
   unsigned int x    = 0;  
   unsigned int i    = 0;  
   for(i = 0; i < len; str++, i++)  
   {  
      hash = (hash << 4) + (*str);  
      if((x = hash & 0xF0000000L) != 0)  
      {  
         hash ^= (x >> 24);  
      }  
      hash &= ~x;  
   }  
   return hash;  
}  


static void domain_list_ops(struct domin_info_update *msg,unsigned int hashValue ){
    struct domin_info_update *pre;
    struct domin_info_update *find;

    unsigned int hashId  = hashValue&DOMAIN_HASH_SIZE; 

    pre = find = g_domian_hash_list[hashId];

    while(find){
        if (find->hashValue == hashValue &&
            strcmp(find->domain_name,msg->domain_name)==0&&
            strcmp(find->zone_name,msg->zone_name)==0&&
            strcmp(find->host,msg->host)==0){
            break;
        }
        pre = find;
        find = find->next;
    }
    if (msg->action == DOMAN_ACTION_ADD){
        if (find == NULL){
            //add to head
            msg->next = g_domian_hash_list[hashId];
            g_domian_hash_list[hashId] = msg;
            g_domain_num++;
            msg->hashValue = hashValue;
           
        }else{
            free(msg);
        }
    }else {
        // ɾ��ƥ������
        if (find != NULL && pre != NULL ){
            pre->next = find->next;
            if (find == g_domian_hash_list[hashId]){
                g_domian_hash_list[hashId] = find->next;
            }
            free(find);
            g_domain_num--;
        }
        free(msg);
    }
  
}

// to optimization
static void domain_info_store(struct domin_info_update *msg){

    rte_rwlock_write_lock(&domian_list_lock);
    unsigned int  hash_v = elfHash(msg->domain_name, strlen(msg->domain_name));
    domain_list_ops(msg, hash_v);   

    rte_rwlock_write_unlock(&domian_list_lock);
}


//  each master��slave call this func
void domain_msg_ring_create(void){

    if (kdns_status == NULL){
        domain_info_preprocess();    
    }
    char ring_name[64]={0};
    unsigned lcore_id = rte_lcore_id();
    snprintf(ring_name, sizeof(ring_name), "msg_ring_core%d", lcore_id);
        domian_msg_ring[lcore_id] = rte_ring_create(ring_name, MSG_RING_SIZE,
                rte_socket_id(), 0);
        if (unlikely(NULL == domian_msg_ring[lcore_id])) {
            log_msg(LOG_ERR, "Fail to create ring :%s  !\n",ring_name);
            exit(-1) ;
        }
}


void doman_msg_master_process(void){
    
    struct domin_info_update *msg;   
    unsigned cid_master = get_master_lcore_id();
    unsigned idx =0;
    
    while (0 == rte_ring_dequeue(domian_msg_ring[cid_master], (void **)&msg)) {
        
        if (g_domain_num > EXTRA_DOMAIN_NUMBERS - 100){
            log_msg(LOG_ERR,"domain len reach threadHold(%d): domian(%s) host(%s) \n", EXTRA_DOMAIN_NUMBERS,
                    msg->domain_name,msg->host);
            free(msg);
            continue;
         }
        //dispatch the msg
        for(idx =0; idx < MAX_CORES; idx ++){

            // skip the master
            if ( domian_msg_ring[idx] == NULL || idx == cid_master){
                continue;
            }
            struct domin_info_update * new_msg = msg_copy(msg);
            int res = rte_ring_enqueue(domian_msg_ring[idx], (void *)new_msg);

            if (unlikely(-EDQUOT == res)) {
                printf(" msg_ring of lcore %d quota exceeded\n", idx);
           } else if (unlikely(-ENOBUFS == res)) {
                log_msg(LOG_ERR," msg_ring of lcore %d is full\n", idx);
                free(new_msg);
           } else if (res) {
                log_msg(LOG_ERR,"unkown error %d for rte_ring_enqueue lcore %d\n", res,idx);
                free(new_msg);
           }
             
        }
        // last we free the msg     
        struct domin_info_update * new_msg_tcp = msg_copy(msg);
        tcp_domian_databd_update(new_msg_tcp);
      
        domain_info_store(msg); 
    }   
}

void doman_msg_slave_process(void){
    struct domin_info_update *msg;   
    unsigned cid = rte_lcore_id();    
    while (0 == rte_ring_dequeue(domian_msg_ring[cid], (void **)&msg)) {   
        domaindata_update(dpdk_dns[cid].db,msg);
        free(msg); 
    }   
}

static void send_domain_msg_to_master(struct domin_info_update *msg){ 
    
    unsigned cid_master = get_master_lcore_id();
    
    assert(msg);
    int res = rte_ring_enqueue(domian_msg_ring[cid_master],(void *) msg);

    if (unlikely(-EDQUOT == res)) {
        log_msg(LOG_ERR," msg_ring of master lcore %d quota exceeded\n", cid_master);
   } else if (unlikely(-ENOBUFS == res)) {
        log_msg(LOG_ERR," msg_ring of master lcore %d is full\n", cid_master);
        free(msg);
   } else if (res) {
        log_msg(LOG_ERR,"unkown error %d for rte_ring_enqueue master lcore %d\n", res,cid_master);
        free(msg);
   } 
   return ;
}


static inline int ipv4_address_check(const char *str)  
{  
    struct in_addr addr;  
    return inet_pton(AF_INET, str, &addr);  
}


static void* domaindata_parse(enum db_action   action,struct connection_info_struct *con_info , int * len_response)
{
    char * post_ok = strdup("OK\n");
    char * parseErr = NULL;
    
    if (action == DOMAN_ACTION_ADD){        
        log_msg(LOG_INFO,"add data = %s\n",(char *)con_info->uploaddata);
    }else{ 
        log_msg(LOG_INFO,"del data = %s\n",(char *)con_info->uploaddata);
    }
    *len_response = strlen(post_ok);


   struct domin_info_update *update = calloc(1,sizeof(struct domin_info_update));
   update->action = action;
    /* parse json object */
    json_error_t jerror;
    const char * value ;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror); 
    if (!json_response) {
        log_msg(LOG_ERR,"load json string  failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto parse_err;
    }
    if (!json_is_object(json_response)) {
        log_msg(LOG_ERR,"load json string failed: not an object!\n");
        json_decref(json_response);
        goto parse_err;
    }

    /* get zone name  */
    json_t *json_key = json_object_get(json_response, "zoneName");
    if (!json_key || !json_is_string(json_key))  {
        log_msg(LOG_ERR,"zoneName does not exist or is not string!");
        json_decref(json_response);
        goto parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->zone_name, strlen(value)+1, "%s", value);
    
    /* get domain name  */
    json_key = json_object_get(json_response, "domainName");
    if (!json_key || !json_is_string(json_key))  {
        log_msg(LOG_ERR,"domainName does not exist or is not string!");
        json_decref(json_response);
        goto parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->domain_name, strlen(value)+1, "%s", value);

     /* get ttl  */
    json_key = json_object_get(json_response, "ttl");
    if (!json_key || !json_is_integer(json_key))  {
        update->ttl = 30;
    }else{  
        update->ttl= json_integer_value(json_key);
    }

     /* get maxAnswer  */
    json_key = json_object_get(json_response, "maxAnswer");
    if (!json_key || !json_is_integer(json_key))  {
        update->maxAnswer = 0;
    }else{  
        update->maxAnswer = json_integer_value(json_key);
    }

    /* get type name  */
    json_key = json_object_get(json_response, "type");
    if (!json_key || !json_is_string(json_key))  {
        log_msg(LOG_ERR,"type does not exist or is not string!");
        json_decref(json_response);
        goto parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->type_str, strlen(value)+1, "%s", value);
    if (strcmp(update->type_str, "A") == 0) {
        update->type = TYPE_A;
    }else if (strcmp(update->type_str, "PTR") == 0) {
        update->type = TYPE_PTR;
    }else if (strcmp(update->type_str, "CNAME") == 0) {
        update->type = TYPE_CNAME;
    }else if (strcmp(update->type_str, "SRV") == 0) {
        update->type = TYPE_SRV;
    }else {
        log_msg(LOG_ERR,"type not support!");
        json_decref(json_response);
        goto parse_err;
    }
    if (update->type == TYPE_A){
            /* get view name  */
           json_key = json_object_get(json_response, "viewName");
           if (!json_key || !json_is_string(json_key))  {
                memcpy(update->view_name, DEFAULT_VIEW_NAME, strlen(DEFAULT_VIEW_NAME)); 
            }else{  
                value = json_string_value(json_key);
                snprintf(update->view_name, strlen(value)+1, "%s", value);
            }
            /* get lb info*/
            json_key = json_object_get(json_response, "lbMode");
            if (!json_key || !json_is_integer(json_key))  {
                update->lb_mode = 0;
            }else{  
                update->lb_mode= json_integer_value(json_key);
            }
            json_key = json_object_get(json_response, "lbWeight");
            if (!json_key || !json_is_integer(json_key))  {
                update->lb_weight= 0;
            }else{  
                update->lb_weight= json_integer_value(json_key);
            }
        /* get ip addr  */
           json_key = json_object_get(json_response, "host");
           if (!json_key || !json_is_string(json_key))  {
               log_msg(LOG_ERR,"host does not exist or is not string!");
               json_decref(json_response);
               goto parse_err;
           }
           value = json_string_value(json_key);
           if (ipv4_address_check(value) <= 0){
               log_msg(LOG_ERR,"host is not an ipv4 addr\n!");
               json_decref(json_response);
               goto parse_err;
           }
           snprintf(update->host, strlen(value)+1, "%s", value);     
    } else if (update->type == TYPE_PTR || update->type == TYPE_CNAME){
        /* get host */
       json_key = json_object_get(json_response, "host");
       if (!json_key || !json_is_string(json_key))  {
           log_msg(LOG_ERR,"host does not exist or is not string!");
           json_decref(json_response);
           goto parse_err;
       }
       value = json_string_value(json_key);
       snprintf(update->host, strlen(value)+1, "%s", value);     
    } else if (update->type == TYPE_SRV){
        /* get host  */
       json_key = json_object_get(json_response, "host");
       if (!json_key || !json_is_string(json_key))  {
           log_msg(LOG_ERR,"ipAddr does not exist or is not string!");
           json_decref(json_response);
           goto parse_err;
       }
       value = json_string_value(json_key);
       snprintf(update->host, strlen(value)+1, "%s", value);  

         /* get priority  */
        json_key = json_object_get(json_response, "priority");
        if (!json_key || !json_is_integer(json_key))  {
            log_msg(LOG_ERR,"priority does not exist or is not int!");
            json_decref(json_response);
            goto parse_err;
        }
        update->prio = json_integer_value(json_key);

         /* get weight  */
        json_key = json_object_get(json_response, "weight");
        if (!json_key || !json_is_integer(json_key))  {
            log_msg(LOG_ERR,"weight does not exist or is not int!");
            json_decref(json_response);
            goto parse_err;
        }
        update->weight= json_integer_value(json_key);

         /* get port  */
        json_key = json_object_get(json_response, "port");
        if (!json_key || !json_is_integer(json_key))  {
            log_msg(LOG_ERR,"port does not exist or is not int!");
            json_decref(json_response);
            goto parse_err;
        }
        update->port = json_integer_value(json_key);
    } 

    send_domain_msg_to_master(update);
    
    json_decref(json_response);

    return post_ok;

 parse_err:   
   parseErr = strdup("parse data err\n");
    *len_response = strlen(parseErr);
    return (void* )parseErr;
}
static void* domain_post(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response){
    return domaindata_parse(DOMAN_ACTION_ADD,con_info,len_response);
}


static void* domain_del(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response){   
    return domaindata_parse(DOMAN_ACTION_DEL,con_info,len_response);
}


static void* domains_get( __attribute__((unused)) struct connection_info_struct *con_info,__attribute__((unused))char *url, int * len_response)
{
    char * outErr = NULL;
    struct domin_info_update *domain_info;
    log_msg(LOG_INFO,"domain_get() in \n");

    json_t * array = json_array();

    if(!array){
        log_msg(LOG_ERR,"unable to create array\n");
        outErr = strdup("unable to create array");        
        goto err_out;
    }

    json_t *value = NULL;
  
    rte_rwlock_read_lock(&domian_list_lock);
    int i =0;
    for (i =0; i < DOMAIN_HASH_SIZE; i++ ){
        domain_info = g_domian_hash_list[i];

        while(domain_info){
            switch (domain_info->type){
                case TYPE_A:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type","A",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "view",domain_info->view_name,"ttl", domain_info->ttl,"maxAnswer", domain_info->maxAnswer,
                    "lbMode",domain_info->lb_mode,"lbWeight",domain_info->lb_weight);
                    break;    
                 case TYPE_PTR:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i, s:i}", "type","PTR",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl,"maxAnswer", domain_info->maxAnswer);
                    break;
                 case TYPE_CNAME:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i, s:i}", "type","CNAME",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl,"maxAnswer", domain_info->maxAnswer);
                    break;
                 case TYPE_SRV:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i, s:i}", "type","SRV",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl, "priority", domain_info->prio, "weight", domain_info->weight, "port", domain_info->port,
                    "maxAnswer", domain_info->maxAnswer);
                    break;
                default:  
                    log_msg(LOG_ERR,"wrong type(%d) domain:%s\n", domain_info->type, domain_info->domain_name);
            }

            json_array_append_new(array, value);
            domain_info = domain_info->next;
        }
    }
    rte_rwlock_read_unlock(&domian_list_lock);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO,"domain_get() out \n");
    return (void* )str_ret;;

err_out:  
    rte_rwlock_read_unlock(&domian_list_lock);
    *len_response = strlen(outErr);
     log_msg(LOG_INFO,"domain_get() err out \n");
    return (void* )outErr;
}


static void* domain_get( __attribute__((unused)) struct connection_info_struct *con_info, char* url, int * len_response)
{
    char domain[128]={0};
    char *ptr = strrchr(url, '/');
    sprintf(domain,"%s",ptr+1);

    char * outErr = NULL;
    log_msg(LOG_INFO,"domain_get() in \n");

    json_t * array = json_array();

    if(!array){
        log_msg(LOG_ERR,"unable to create array\n");
        outErr = strdup("unable to create array");        
        goto err_out;
    }

    json_t *value = NULL;

    
    unsigned int  hashValue = elfHash(domain, strlen(domain));

    unsigned int hashId  = hashValue&DOMAIN_HASH_SIZE; 
    
    rte_rwlock_read_lock(&domian_list_lock);

    struct domin_info_update *domain_info = g_domian_hash_list[hashId];

    while(domain_info){
        if (domain_info->hashValue == hashValue &&
            strcmp(domain_info->domain_name,domain)==0){
              switch (domain_info->type){
                case TYPE_A:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type","A",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "view",domain_info->view_name,"ttl", domain_info->ttl,"maxAnswer", domain_info->maxAnswer,
                    "lbMode",domain_info->lb_mode,"lbWeight",domain_info->lb_weight);
                    break;    
                 case TYPE_PTR:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i}", "type","PTR",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl);
                    break;
                 case TYPE_CNAME:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i}", "type","CNAME",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl);
                    break;
                 case TYPE_SRV:
                    value = json_pack("{s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type","SRV",
                    "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                    "ttl", domain_info->ttl, "priority", domain_info->prio, "weight", domain_info->weight, "port", domain_info->port);
                    break;
                default:  
                    log_msg(LOG_ERR,"wrong type(%d) domain:%s\n", domain_info->type, domain_info->domain_name);
        
             }
             json_array_append_new(array, value);
        }
        domain_info = domain_info->next;
    }

    rte_rwlock_read_unlock(&domian_list_lock);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO,"domain_get() out \n");
    return (void* )str_ret;;

err_out:  
    rte_rwlock_read_unlock(&domian_list_lock);
    *len_response = strlen(outErr);
     log_msg(LOG_INFO,"domain_get() err out \n");
    return (void* )outErr;
}



static int domain_num_get(void)
{
    int num =0;
    rte_rwlock_read_lock(&domian_list_lock);
    num = g_domain_num;
    rte_rwlock_read_unlock(&domian_list_lock);
    return num;
}


static void* kdns_status_post(__attribute__((unused)) struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response)
{
    char * post_ok = strdup("OK\n");
    kdns_status = strdup(DNS_STATUS_RUN);  
    *len_response = strlen(post_ok);
    return (void* )post_ok;
}


static void* kdns_status_get(__attribute__((unused)) struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response)
{
    char * get_ok = strdup(kdns_status);
    *len_response = strlen(get_ok);
    return (void* )get_ok;
}


struct json_stats_strings
{
    char  domain_num[32]; 
    char  pkts_rcv[32];  
    char  pkts_2kni[32]; 
    char  pkts_icmp[32]; 
    char dns_pkts_rcv[32]; 
    char dns_pkts_snd[32]; 
    char dns_lens_rcv[32]; 
    char dns_lens_snd[32];
    char pkt_dropped[32];
    char pkt_len_err[32];      
};

static void* statistics_get( __attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused))char *url,int * len_response)
{
    struct netif_queue_stats sta ={0};
    netif_statsdata_get(&sta);

    struct json_stats_strings sta_string ={"","","","","","","","","",""};

    sprintf(sta_string.domain_num,"%d",domain_num_get());
    sprintf(sta_string.pkts_rcv,"%ld",sta.pkts_rcv);
    sprintf(sta_string.dns_pkts_rcv,"%ld",sta.dns_pkts_rcv);
    sprintf(sta_string.dns_pkts_snd,"%ld",sta.dns_pkts_snd);
    sprintf(sta_string.dns_lens_rcv,"%ld",sta.dns_lens_rcv);
    sprintf(sta_string.dns_lens_snd,"%ld",sta.dns_lens_snd);
    sprintf(sta_string.pkt_dropped,"%ld",sta.pkt_dropped);
    sprintf(sta_string.pkts_2kni,"%ld",sta.pkts_2kni);
    sprintf(sta_string.pkts_icmp,"%ld",sta.pkts_icmp);
    sprintf(sta_string.pkt_len_err,"%ld",sta.pkt_len_err);

    
    json_t *value = NULL;
    
    value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s}", 
            "domain_num",sta_string.domain_num, "pkts_rcv",sta_string.pkts_rcv,
            "dns_pkts_rcv",sta_string.dns_pkts_rcv,"dns_pkts_snd",sta_string.dns_pkts_snd,"pkt_dropped",sta_string.pkt_dropped,
            "pkts_2kni",sta_string.pkts_2kni,"pkts_icmp",sta_string.pkts_icmp,"pkt_len_err",sta_string.pkt_len_err,
            "dns_lens_rcv",sta_string.dns_lens_rcv,"dns_lens_snd",sta_string.dns_lens_snd);
    
    if (!value){
           char * err = strdup("json_pack err");
           *len_response = strlen(err);
           return (void* )err;;  
    }
    
    char *str_ret = json_dumps(value, JSON_COMPACT);
    json_decref(value);
    *len_response = strlen(str_ret);
    return (void* )str_ret;;
}


static void* statistics_reset( __attribute__((unused)) struct connection_info_struct *con_info,__attribute__((unused))char *url, int * len_response)
{
    char * post_ok = strdup("OK\n");
    netif_statsdata_reset();
    *len_response = strlen(post_ok);
    return (void* )post_ok;
}



void domian_info_exchange_run( int port){
    
    dins = webserver_new(port);
    web_endpoint_add("POST","/kdns/domain",dins,&domain_post);
    web_endpoint_add("GET","/kdns/domain",dins,&domains_get);
    web_endpoint_add("GET","/kdns/perdomain/",dins,&domain_get);
    web_endpoint_add("DELETE","/kdns/domain",dins,&domain_del);

    web_endpoint_add("POST","/kdns/status",dins,&kdns_status_post);
    web_endpoint_add("GET","/kdns/status",dins,&kdns_status_get);

    web_endpoint_add("GET","/kdns/statistics/get",dins,&statistics_get);
    web_endpoint_add("POST","/kdns/statistics/reset",dins,&statistics_reset);
    
    web_endpoint_add("POST","/kdns/view",dins,&view_post);
    web_endpoint_add("GET","/kdns/view",dins,&view_get);
    //web_endpoint_add("GET","/kdns/perview",dins,&domain_get);
    web_endpoint_add("DELETE","/kdns/view",dins,&view_del);
    
    webserver_run(dins);
    return;   
}

