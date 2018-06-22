/* Process model C form file: tcp_manager_v3_dt.pr.c */
/* Portions of this file copyright 1992-2004 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char tcp_manager_v3_dt_pr_c [] = "MIL_3_Tfile_Hdr_ 110A 30A op_runsim 7 46E9AD77 46E9AD77 1 zeus momueti 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 b56 1                                                                                                                                                                                                                                                                                                                                                                                                            ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <ip_addr_v4.h>
#include <oms_dt.h>
#include <tcp_api_v3.h>
#include <tcp_v3.h>
#include <tcp_support.h>
#include <oms_pr.h>
#include <oms_tan.h>
#include <tcp_seg_sup.h>
#include <ip_notif_log_support.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ip_higher_layer_proto_reg_sup.h>
#include <ip_qos_support.h>

/* Transition macros */                                      
#define OPEN			((intrpt_type == OPC_INTRPT_REMOTE) &&			\
						((intrpt_code == TCPC_COMMAND_OPEN_ACTIVE) ||	\
						(intrpt_code == TCPC_COMMAND_OPEN_PASSIVE)))
#define SEND			((intrpt_type == OPC_INTRPT_STRM) && 			\
						(intrpt_strm > TCPC_INSTRM_NETWORK))
#define RECEIVE			((intrpt_type == OPC_INTRPT_REMOTE) && 			\
						(intrpt_code == TCPC_COMMAND_RECEIVE))
#define CLOSE			((intrpt_type == OPC_INTRPT_REMOTE) && 			\
						(intrpt_code == TCPC_COMMAND_CLOSE))
#define ABORT			((intrpt_type == OPC_INTRPT_REMOTE) &&			\
						(intrpt_code == TCPC_COMMAND_ABORT))
#define SEG_ARRIVAL		((intrpt_type == OPC_INTRPT_STRM) &&			\
						(intrpt_strm == TCPC_INSTRM_NETWORK))
#define STATUS_IND		((intrpt_type == OPC_INTRPT_REMOTE) &&			\
						(intrpt_code == TCPC_COMMAND_STATUS_IND))

/* End of simulation interrupt for statistic update */
#define END_SIM			(intrpt_type == OPC_INTRPT_ENDSIM)

/* Failure recover interrupts.	*/
#define FAILURE_RECOVERY (((intrpt_type == OPC_INTRPT_FAIL) || (intrpt_type == OPC_INTRPT_RECOVER)) \
	                     && (op_intrpt_source () == own_node_objid))

/* Define the number of connections for which statistics have to be recorded */
#define	CONNECTION_STATISTIC_COUNT	32
#define CONN_NOT_USED				-99

/* Global variables.	*/
static TcpT_Ip_Encap_Req_Ici_Info	ip_encap_ici_info;
static Boolean						ici_print_procs_set = OPC_FALSE;
static Boolean						log_call_scheduled = OPC_FALSE;

/*	Prototypes for functions in this process model.	*/
static void			tcp_mgr_sv_init (void);
static void			tcp_mgr_rst_send (int seq_num, int ack, int ack_num, TcpT_Port local_port,
						InetT_Address orig_addr, TcpT_Port orig_port, InetT_Address local_addr,
						OmsT_Dt_Key local_key, OmsT_Dt_Key remote_key);
static void			tcp_mgr_error (const char* msg);
static void			tcp_mgr_warn (const char* msg);
static void			tcp_connection_based_statistics_register (TcpT_Tcb* tcb_ptr, Boolean active_session);
static int 			tcp_mgr_next_avail_port_find (void);
static Compcode 	tcp_mgr_port_availability_check (int requested_local_port);
static void			tcp_mgr_tcp_params_parse (void);
static Boolean		tcp_active_conn_count_reached (void);




/* End of Header Block */


#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
typedef struct
	{
	/* Internal state tracking for FSM */
	FSM_SYS_STATE
	/* State Variables */
	List*	                  		tcb_list                                        ;
	TcpT_Conn_Parameters*	  		tcp_parameter_ptr                               ;	/* Structure storing the "TCP Parameters" to be passed to the tcp_conn_v3 process on its creation.	 */
	TcpT_Ptc_Mem	           		tcp_ptc_mem                                     ;	/* Encompassing structure containing both the "tcp_conn_ptr" and "tcb_ptr" */
	int	                    		conn_id_new                                     ;
	TcpT_Event*	            		ev_ptr                                          ;
	TcpT_Diag*	             		diag_ptr                                        ;
	int	                    		tcp_trace_active                                ;
	int*	                   		local_port_ptr                                  ;	/* This pointer is registered in the model wide object registry */
	                        		                                                	/* and is kept uptodate with the next available local port on 	 */
	                        		                                                	/* this node. Any application that registers with the TCP API 	 */
	                        		                                                	/* package can use this value to create a connection on the 	   */
	                        		                                                	/* next available port.											                              */
	Objid	                  		own_mod_objid                                   ;
	Objid	                  		own_node_objid                                  ;
	Prohandle	              		own_prohandle                                   ;
	OmsT_Pr_Handle	         		own_process_record_handle                       ;
	char	                   		proc_model_name[20]                             ;
	Stathandle	             		packet_load_handle                              ;
	Stathandle	             		byte_load_handle                                ;
	Stathandle	             		packet_sec_load_handle                          ;
	Stathandle	             		byte_sec_load_handle                            ;
	Stathandle	             		abort_conn_stathandle                           ;
	Log_Handle	             		ll_loghndl                                      ;	/* Notification log handles.	 */
	Boolean	                		port_values_wrapped_around                      ;	/* This flag keeps status on the port values being assigned for the  */
	                        		                                                	/* tcp connections that are initiated by this node. Before the port  */
	                        		                                                	/* values reach the MAX assignable port value, the next available    */
	                        		                                                	/* port value is computed simply by incremententing the current port */
	                        		                                                	/* value by 1. But once the values wrap around, we have to search    */
	                        		                                                	/* through the list of available tcp connections and find an unused  */
	                        		                                                	/* port.                                                             */
	OmsT_Dt_Handle	         		tcp_dt_handle                                   ;	/* A dispatch table used to manage spawned TCP connections. */
	LlmT_Lan_Handle	        		my_lanhandle                                    ;	/* LAN handle, if the surrounding node is a LAN node. */
	int	                    		lan_server_identifier                           ;	/* Server identifier, if the surrounding node is a LAN object. */
	                        		                                                	/* Note that each LAN object can only have one server.         */
	Stathandle	             		glbl_active_conn_handle                         ;
	Stathandle	             		active_conn_handle                              ;
	Boolean	                		print_conn_info                                 ;	/* User specified attribute of whether the TCP Connection Information should be printed or not */
	int	                    		max_connections                                 ;	/* The maximum number of TCP concurrent connections. */
	Boolean	                		num_sess_reach_log_written                      ;	/* Indicates whether a log informing the user that the maximum 	 */
	                        		                                                	/* number of concurrent sessions has been written. This log		    */
	                        		                                                	/* message should be written out only once per node.			          */
	PrgT_String_Hash_Table*			log_msg_hash_table                              ;	/* Hash table to print messages about possible configuration problems	 */
	Stathandle	             		blocked_conn_count_stathandle                   ;	/* For tracking number of connections blocked after the active connection threshold is reached. */
	} tcp_manager_v3_dt_state;

#define pr_state_ptr            		((tcp_manager_v3_dt_state*) (OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))
#define tcb_list                		pr_state_ptr->tcb_list
#define tcp_parameter_ptr       		pr_state_ptr->tcp_parameter_ptr
#define tcp_ptc_mem             		pr_state_ptr->tcp_ptc_mem
#define conn_id_new             		pr_state_ptr->conn_id_new
#define ev_ptr                  		pr_state_ptr->ev_ptr
#define diag_ptr                		pr_state_ptr->diag_ptr
#define tcp_trace_active        		pr_state_ptr->tcp_trace_active
#define local_port_ptr          		pr_state_ptr->local_port_ptr
#define own_mod_objid           		pr_state_ptr->own_mod_objid
#define own_node_objid          		pr_state_ptr->own_node_objid
#define own_prohandle           		pr_state_ptr->own_prohandle
#define own_process_record_handle		pr_state_ptr->own_process_record_handle
#define proc_model_name         		pr_state_ptr->proc_model_name
#define packet_load_handle      		pr_state_ptr->packet_load_handle
#define byte_load_handle        		pr_state_ptr->byte_load_handle
#define packet_sec_load_handle  		pr_state_ptr->packet_sec_load_handle
#define byte_sec_load_handle    		pr_state_ptr->byte_sec_load_handle
#define abort_conn_stathandle   		pr_state_ptr->abort_conn_stathandle
#define ll_loghndl              		pr_state_ptr->ll_loghndl
#define port_values_wrapped_around		pr_state_ptr->port_values_wrapped_around
#define tcp_dt_handle           		pr_state_ptr->tcp_dt_handle
#define my_lanhandle            		pr_state_ptr->my_lanhandle
#define lan_server_identifier   		pr_state_ptr->lan_server_identifier
#define glbl_active_conn_handle 		pr_state_ptr->glbl_active_conn_handle
#define active_conn_handle      		pr_state_ptr->active_conn_handle
#define print_conn_info         		pr_state_ptr->print_conn_info
#define max_connections         		pr_state_ptr->max_connections
#define num_sess_reach_log_written		pr_state_ptr->num_sess_reach_log_written
#define log_msg_hash_table      		pr_state_ptr->log_msg_hash_table
#define blocked_conn_count_stathandle		pr_state_ptr->blocked_conn_count_stathandle

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#  define FIN_PREAMBLE_DEC	tcp_manager_v3_dt_state *op_sv_ptr;
#if defined (OPD_PARALLEL)
#  define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((tcp_manager_v3_dt_state *)(sim_context_ptr->_op_mod_state_ptr));
#else
#  define FIN_PREAMBLE_CODE	op_sv_ptr = pr_state_ptr;
#endif


/* Function Block */


#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ };
#endif
static void
tcp_mgr_sv_init (void)
	{
	/** Initializes the state variables used in this model.	**/
	FIN (tcp_mgr_sv_init ())

	/* Initialize variables used for process registry.	*/
	/* Obtain the tcp2 module's objid. */
	own_mod_objid = op_id_self ();
	
	/* Obtain the node's objid. */
	own_node_objid = op_topo_parent (own_mod_objid);

	/* Obtain the tcp_manager2 process's prohandle. */
	own_prohandle = op_pro_self ();
	
	/* Obtain the name of the process. It is the "process model" attribute of the node. */
	op_ima_obj_attr_get (own_mod_objid, "process model", proc_model_name);
	
	/* Register stat handles */
	byte_load_handle		= op_stat_reg ("TCP.Load (bytes)",       		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	packet_load_handle		= op_stat_reg ("TCP.Load (packets)",    		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	byte_sec_load_handle	= op_stat_reg ("TCP.Load (bytes/sec)",  		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	packet_sec_load_handle	= op_stat_reg ("TCP.Load (packets/sec)", 		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	abort_conn_stathandle	= op_stat_reg ("TCP.Connection Aborts",	 		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
    active_conn_handle      = op_stat_reg ("TCP.Active Connection Count",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	blocked_conn_count_stathandle = op_stat_reg ("TCP.Blocked Connection Count",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	/* Initialize the diagnostic structure dynamic array pointer */
	diag_ptr = (TcpT_Diag *) op_prg_mem_alloc (CONNECTION_STATISTIC_COUNT * sizeof (TcpT_Diag));

	/* Init Vars. */
	conn_id_new = 1;

	tcb_list = op_prg_list_create ();
	if (tcb_list == OPC_NIL)
		{
		op_prg_log_entry_write (ll_loghndl, "TCP initialization failed - unable to create TCB list.");
		op_sim_end ("TCP initialization failed - unable to create TCB list.", 
					"Please check simulation log for simulation kernel errors.", "", "");
		}

	/* Create the ici that will be used to communicate with IP.			*/
	/* Do this only if another node has not done this already.			*/
	if (ip_encap_ici_info.ip_encap_req_ici_ptr == OPC_NIL)
		{
		ip_encap_ici_info.ip_encap_req_ici_ptr = op_ici_create ("inet_encap_req");
		}

	if (ip_encap_ici_info.ip_encap_req_ici_ptr == OPC_NIL)
		{
		op_prg_log_entry_write (ll_loghndl,
				"TCP initialization failed - unable to create ICI for communication with IP.");
		op_sim_end ("TCP initialization failed - unable to create ICI for communication with IP.", 
					"Please check simulation log for simulation kernel errors.", "", "");
		}

	/* Set the dest_addr and src_addr fields in the ici. Every time we	*/
	/* need to send an packet, we just need to set the variables used	*/
	/* here appropriately. No need to call op_ici_attr_set.				*/
	if ((op_ici_attr_set (ip_encap_ici_info.ip_encap_req_ici_ptr, "dest_addr",
			&(ip_encap_ici_info.dest_addr)) == OPC_COMPCODE_FAILURE) ||
		(op_ici_attr_set (ip_encap_ici_info.ip_encap_req_ici_ptr, "src_addr",
			&(ip_encap_ici_info.src_addr))  == OPC_COMPCODE_FAILURE))
		{
		op_prg_log_entry_write (ll_loghndl,
				"TCP initialization failed - unable to set address in ICI for communication with IP.");
		op_sim_end ("TCP initialization failed - unable to set address in ICI for communication with IP.", 
					"Please check simulation log for simulation kernel errors.", "", "");
		}
		
	/* Register the print proc for the InetT_Address fields in Icis.	*/
	if (OPC_FALSE == ici_print_procs_set)
		{
		op_ici_format_print_proc_set ("tcp_command_v3", "rem_addr",   inet_address_ici_field_print);	
		op_ici_format_print_proc_set ("tcp_command_v3", "local_addr", inet_address_ici_field_print);	
		op_ici_format_print_proc_set ("tcp_open_ind_inet","rem addr",   inet_address_ici_field_print);	

		ici_print_procs_set = OPC_TRUE;
		}

	/* Allocate memory for the structure storing the "TCP Parameters".	*/
	/* This structure would be passed to the tcp_conn_v3 process along	*/
	/* with the TCB information.										*/
	tcp_parameter_ptr = (TcpT_Conn_Parameters *) op_prg_mem_alloc (sizeof (TcpT_Conn_Parameters));
	if (tcp_parameter_ptr == OPC_NIL)
		{
		tcp_mgr_error ("Unable to allocate memory for TCP connection parameters.");
		}

	/* Parse the "TCP Parameters" attribute from the manager's model 	*/
	/* attributes and store it in the tcp_parameter_ptr structure			*/
	tcp_mgr_tcp_params_parse ();

	/* Set the next available local port to the minimum available port	*/
	/* number (1025). This pointer will be registered in the model wide	*/
	/* wide registry and the used by TCP API package.					*/ 
	local_port_ptr = (int *)op_prg_mem_alloc (sizeof (int));
	*local_port_ptr = TCPC_MIN_ASSIGNABLE_PORT;
	port_values_wrapped_around = OPC_FALSE;

    /* Create a log handle for the low_level errors,        */
	/* which are reported directly by this process model.   */
	ll_loghndl = op_prg_log_handle_create (OpC_Log_Category_Lowlevel, "TCP", "Kernel_Error", 25);
	
	/* Indicates that a log message has not been written for this node.	*/
	num_sess_reach_log_written = OPC_FALSE;

	FOUT
	}

static void
tcp_mgr_tcp_params_parse ()
	{
	Objid 		tcp_parameter_comp_objid;
	Objid 		tcp_parameter_objid;
	Boolean		window_scaling_enabled = OPC_FALSE;
	double		max_ack_delay = 0.0;
	Objid		timestamp_attr_id;
	Objid		timestamp_values_id;
	Objid		retrans_limit_cmp_attr_id;
	Objid		retrans_limit_values_id;

	/** Parses the model attributes of the tcp_manager and stores them in the		**/
	/** tcp_parameter_ptr structure. This structure is further passed to individual	**/
	/** tcp connection processes upon their creation.								**/
	FIN (tcp_mgr_tcp_params_parse ());

	/* Obtain the objid of compound attibute which stores all the "TCP Parametera"	*/
	op_ima_obj_attr_get (own_mod_objid, "TCP Parameters", &tcp_parameter_comp_objid);
	tcp_parameter_objid = op_topo_child (tcp_parameter_comp_objid, OPC_OBJTYPE_GENERIC, 0);

	/* Initialize maximum segment size and congestion-control variables. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Maximum Segment Size", 
		&tcp_parameter_ptr->max_seg_size) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get MSS from attribute.");
	
	/* Read the architecture flavor.	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Receive Buffer Adjustment", 
		&tcp_parameter_ptr->rcv_buff_adj) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"Receive Buffer Adjustment\" from attribute.");

	/* Determine receiving buffer size (in bytes).  This value			*/
	/* limits the number of segments that can be held by the process.	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Receive Buffer", 
		&tcp_parameter_ptr->rcv_buff_size) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Receive Buffer from attribute.");

	/* Determine the threshold used to determine the limit on	*/
	/* the usage of receive buffer before transferring segments	*/
	/* from it to the socket buffer.							*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Receive Buffer Usage Threshold", 
		&tcp_parameter_ptr->rcv_buff_thresh) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Receive Buffer Usage Threshold attribute.");
		
	/* Determine whether Window Scaling is enabled for this host */
	if (op_ima_obj_attr_get(tcp_parameter_objid, "Window Scaling", 
		&tcp_parameter_ptr->window_scaling_flag) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Window Scaling attribute.");
	
	/* Read ACK Frequency.											*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Maximum ACK Segments",
		&tcp_parameter_ptr->ack_frequency) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Maximum unACKed Segment Count.");
	
	/* Determine whether TCP Timestamp option is supported. 	*/
	op_ima_obj_attr_get (tcp_parameter_objid, "Timestamp", &timestamp_attr_id);
	timestamp_values_id = op_topo_child (timestamp_attr_id, OPC_OBJTYPE_GENERIC, 0);
	
	/* Read in the values for the different retransmission limits.		*/
	if (op_ima_obj_attr_get (timestamp_values_id, "Status", 
			&tcp_parameter_ptr->timestamp_flag) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (timestamp_values_id, "Clock Tick", 
			&tcp_parameter_ptr->timestamp_clock) == OPC_COMPCODE_FAILURE)
		{
		tcp_mgr_error ("Unable to get Timestamp attribute.");
		}
			
	/* Determine the maximum length of time that outgoing ACK's should	*/
	/* be delayed for possible "piggybacking" on outgoing data.			*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Maximum ACK Delay", &max_ack_delay) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get maximum ACK delay from attribute.");

	/* Check for a value of 0.0 seconds for max_ack_delay (this will	*/
	/* cause many TCP acknowledgements to be sent) -- log a message		*/
	/* if this is the case.												*/
	if (max_ack_delay == 0.0)
		{
		/*  Check for a setting of 0.0.  This could cause additional    */
		/*  overhead. as there will be no data/ack piggybacking.        */
		tcp_max_ack_zero_log_write ();
		}
	
	/* Store the maxmimum ack delay in the "TCP Parameters" structure	*/
	tcp_parameter_ptr->maximum_ack_delay = max_ack_delay;

	/* Determine the number of MSS-sized packets with which TCP's slow	*/
	/* start will begin. The value indicates the number of segments		*/
	/* that will be sent upon slow-start. This is also the value of the	*/
	/* initial congestion window (or "cwnd").							*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Slow-Start Initial Count", 
		&tcp_parameter_ptr->slow_start_initial_count) == OPC_COMPCODE_FAILURE)
		{
		tcp_mgr_error ("Unable to get slow start initial count from attribute.");
		}
	
	/* Initialize retransmission timeout. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Initial RTO", 
		&tcp_parameter_ptr->initial_rto) == OPC_COMPCODE_FAILURE)
		{
		tcp_mgr_error ("Unable to get initial retransmission timeout value.");
		}
	
	/* Initialize support variables for updating retransmission timeout. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Minimum RTO", 
			&tcp_parameter_ptr->min_rto) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (tcp_parameter_objid, "Maximum RTO", 
			&tcp_parameter_ptr->max_rto) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (tcp_parameter_objid, "RTT Gain", 
			&tcp_parameter_ptr->gain_in_rtt) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (tcp_parameter_objid, "Deviation Gain", 
			&tcp_parameter_ptr->dev_gain) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (tcp_parameter_objid, "RTT Deviation Coefficient", 
			&tcp_parameter_ptr->rtt_dev_coeff) == OPC_COMPCODE_FAILURE)
		{
		tcp_mgr_error ("Unable to get retransmission attributes.");
		}

	/* Obtain the values for the retransmission limits.	These values 	*/
	/* are present under a compound attribute "Retransmission Limits". 	*/
	op_ima_obj_attr_get (tcp_parameter_objid, "Retransmission Thresholds", &retrans_limit_cmp_attr_id);
	retrans_limit_values_id = op_topo_child (retrans_limit_cmp_attr_id, OPC_OBJTYPE_GENERIC, 0);

	/* Read in the values for the different retransmission limits.		*/
	if (op_ima_obj_attr_get (retrans_limit_values_id, "Mode", 
			&tcp_parameter_ptr->mode) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (retrans_limit_values_id, "Maximum Connect Attempts", 
			&tcp_parameter_ptr->max_conn_attempts) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (retrans_limit_values_id, "Maximum Data Attempts", 
			&tcp_parameter_ptr->max_data_attempts) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (retrans_limit_values_id, "Maximum Connect Interval", 
			&tcp_parameter_ptr->max_conn_interval) == OPC_COMPCODE_FAILURE ||
		op_ima_obj_attr_get (retrans_limit_values_id, "Maximum Data Interval", 
			&tcp_parameter_ptr->max_data_interval) == OPC_COMPCODE_FAILURE)
		{
		tcp_mgr_error ("Unable to get retransmission attempt limits.");
		}		

	/* Determine whether Nagle SWS Avoidance is to be used. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Nagle Algorithm", 
		&tcp_parameter_ptr->nagle_flag) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Nagle attribute.");

	/* Determine whether Karn's Algorithm is to be used. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Karn's Algorithm", 
		&tcp_parameter_ptr->karns_algorithm_flag) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Karn's Algorithm attribute.");

	/* Determine if Fast Retransmit algorithm is choosen. This would enable 	*/
	/* mimicing the "TCP Tahoe" implementation if, "Fast Recovery" and SACK		*/
	/* is disabled.																*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Fast Retransmit", 
		&tcp_parameter_ptr->fast_retransmit_flag) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Fast Retransmit attribute.");
	
	/* Get the number of ACKs triggering fast retransmit.	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Duplicate ACK Threshold", 
		&tcp_parameter_ptr->fr_dup_ack_thresh) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Duplicate ACK Threshold attribute.");	

	/* Determine if Fast Recovery algorithm is choosen. This would enable 	*/
	/* mimicing the "TCP  Reno" implementation								*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Fast Recovery", 
		&tcp_parameter_ptr->fast_recovery_mode) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Fast Recovery attribute.");

	/* Determine whether Selective Acknowledgements are enabled for this host */
	if (op_ima_obj_attr_get(tcp_parameter_objid, "Selective ACK (SACK)", 
		&tcp_parameter_ptr->sack_options_flag) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get SACK Option attribute.");

	/* Get the persistence timeout duration. */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Persistence Timeout", 
		&tcp_parameter_ptr->persistence_timeout) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get persistence timeout duration attribute.");

	/* Obtain the scheme used to model delayed acknowledgments.	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Delayed ACK Mechanism", 
		&tcp_parameter_ptr->delayed_ack_scheme) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"Delayed ACK Mechanism\" specification.");

	/* Determine the timer granularity -- the explicit timer ticks at which timer	*/
	/* based events (like retransmissions) are scheduled.							*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Timer Granularity", 
		&tcp_parameter_ptr->timer_granularity) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Timer Granularity attribute.");

	/* Determine the timer granularity -- the explicit timer ticks at which timer	*/
	/* based events (like retransmissions) are scheduled.							*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Connection Information", 
		&print_conn_info) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get Connection Information attribute.");
	
	/* Check the assignment for "segment send threshold". Some simulators may operate */
	/* on a packet (i.e., MSS) boundary. This attribute will help in TCP model		 */
	/* performance comparison for those cases.										 */
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Segment Send Threshold", 
		&tcp_parameter_ptr->seg_snd_thresh) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"Segment Send Threshold\" attribute.");

	/* Determine if ECN capability is enabled. Refer to RFC-3168 for details on ECN	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "ECN Capability", 
		&tcp_parameter_ptr->ecn_capability) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"ECN Capability\" attribute.");
	
	/* Read the value for Initial Sequence number.	*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Initial Sequence Number", 
		&tcp_parameter_ptr->init_seq_num) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"Initial Sequence Number\" attribute.");
	
	/* Determine the maximum allowable number of concurrent TCP connections.		*/
	if (op_ima_obj_attr_get (tcp_parameter_objid, "Active Connection Threshold", 
		&max_connections) == OPC_COMPCODE_FAILURE)
		tcp_mgr_error ("Unable to get \"Active Connection Threshold attribute\".");
	if (max_connections == -1)
		max_connections = OPC_INT_INFINITY;
	
	/* Check seetings for buffer size. If there is a possibility that 	*/
	/* thsi node will experience very poor TCP performance due to 		*/
	/* buffer size settings, write a log message.						*/
	if ((tcp_parameter_ptr->rcv_buff_size * (1 - tcp_parameter_ptr->rcv_buff_thresh)) < tcp_parameter_ptr->max_seg_size)
		{
		tcp_possible_data_transfer_slow_down_log_write (tcp_parameter_ptr->rcv_buff_size, tcp_parameter_ptr->max_seg_size, 
			tcp_parameter_ptr->rcv_buff_thresh);
		}
		
	/* Register Number of connections aborted by TCP layer.			*/
	tcp_parameter_ptr->num_conn_rst_sent_stathandle  = op_stat_reg ("TCP.Connection Aborts (RST Sent)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	tcp_parameter_ptr->num_conn_rst_rcvd_stathandle  = op_stat_reg ("TCP.Connection Aborts (RST Rcvd)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);

	/* Initialize the flag indicating whether the surrounding node failed.	*/
	tcp_parameter_ptr->node_failed = OPC_FALSE;
	
	FOUT;
	}

 
static void
tcp_connection_based_statistics_register (TcpT_Tcb* tcb_ptr, Boolean active_session)
	{
	char			appl_name [64];
	char			stat_annotate_str [2048];
	char			rem_addr_nodename [OMSC_HNAME_MAX_LEN] = "Unknown";
	
	static int		load_byte_stat_dim_size = -1;
	static int		load_packet_stat_dim_size = -1;
	static int		load_bytesec_stat_dim_size = -1;
	static int		load_packetsec_stat_dim_size = -1;
	
	/** Registers the connection based statistics that this process maintains.	**/
	/** The connection based statistics are declared as dimensioned statistics.	**/
	/** Check if the current connection's index is less than the maximum index	**/
	/** of the statistic declaration before registering any statistic.			**/
	FIN (tcp_connection_based_statistics_register (tcb_ptr, active_session));

	/* Cache the maximum indices for the dimensioned statistics used by	*/
	/* this process model.  These are not node-specific as the same		*/
	/* process model resides on all nodes (for that matter, even the	*/
	/* statistic declaration is not node-specific.)						*/
	if (load_byte_stat_dim_size == -1)
		{
		/* Obtain decalared indices for all statistics.	*/
		op_stat_dim_size_get ("TCP Connection.Load (bytes)",		OPC_STAT_LOCAL, &load_byte_stat_dim_size);
		op_stat_dim_size_get ("TCP Connection.Load (packets)",		OPC_STAT_LOCAL, &load_packet_stat_dim_size);
		op_stat_dim_size_get ("TCP Connection.Load (bytes/sec)",	OPC_STAT_LOCAL, &load_bytesec_stat_dim_size);
		op_stat_dim_size_get ("TCP Connection.Load (packets/sec)",	OPC_STAT_LOCAL, &load_packetsec_stat_dim_size);
		}
	
	/* Prepare annotation strings.	*/
	if (tcb_ptr->conn_id < load_byte_stat_dim_size ||
		tcb_ptr->conn_id < load_packet_stat_dim_size ||
		tcb_ptr->conn_id < load_bytesec_stat_dim_size ||
		tcb_ptr->conn_id < load_packetsec_stat_dim_size)
		{
		/* Determine the remote node's name using the remote IP address.	*/
		ipnl_inet_addr_to_nodename (tcb_ptr->rem_addr, rem_addr_nodename);
		oms_tan_dotted_hname_to_underscores (rem_addr_nodename);

		/* Obtain the application names and the node to which connection is made.	*/
		if (active_session == OPC_FALSE)
			{
			tcp_appl_name_from_rem_port_get ((GnaT_App)tcb_ptr->local_port, appl_name);
			sprintf (stat_annotate_str, "Conn %d [%s]: (Port %d) <-> %s (Port %d)",
				tcb_ptr->conn_id, appl_name, tcb_ptr->local_port, rem_addr_nodename, tcb_ptr->rem_port);
			}
		else
			{
			tcp_appl_name_from_rem_port_get ((GnaT_App)tcb_ptr->rem_port, appl_name);
			sprintf (stat_annotate_str, "Conn %d [%s]: (Port %d) <-> %s (Port %d)",
				tcb_ptr->conn_id, appl_name, tcb_ptr->local_port, rem_addr_nodename, tcb_ptr->rem_port);
			}
		
		/* Allocate memory to record statistics.	*/
		tcb_ptr->tcp_conn_stat_ptr = (TcpT_Conn_Stats *) op_prg_mem_alloc (sizeof (TcpT_Conn_Stats));
		}
	else
		{
		/* The connection index is greater than the	*/
		/* dimensions of the declared statistics.	*/
		tcb_ptr->tcp_conn_stat_ptr = OPC_NIL;
		}
			
	/* Register statistics, if within collectable limits.	*/
	if (tcb_ptr->conn_id < load_byte_stat_dim_size)
		{
		/* Register statistics and raname them for easier collection. */
		tcb_ptr->tcp_conn_stat_ptr->load_bytes_stathandle = op_stat_reg ("TCP Connection.Load (bytes)", tcb_ptr->conn_id, OPC_STAT_LOCAL);
		op_stat_annotate (tcb_ptr->tcp_conn_stat_ptr->load_bytes_stathandle, stat_annotate_str);
		}
	
	if (tcb_ptr->conn_id < load_packet_stat_dim_size)
		{
		/* Register statistics and raname them for easier collection. */
		tcb_ptr->tcp_conn_stat_ptr->load_packets_stathandle = op_stat_reg ("TCP Connection.Load (packets)", tcb_ptr->conn_id, OPC_STAT_LOCAL);
		op_stat_annotate (tcb_ptr->tcp_conn_stat_ptr->load_packets_stathandle, stat_annotate_str);
		}
	
	if (tcb_ptr->conn_id < load_bytesec_stat_dim_size)
		{
		/* Register statistics and raname them for easier collection. */
		tcb_ptr->tcp_conn_stat_ptr->load_bytes_sec_stathandle = op_stat_reg ("TCP Connection.Load (bytes/sec)", tcb_ptr->conn_id, OPC_STAT_LOCAL);
		op_stat_annotate (tcb_ptr->tcp_conn_stat_ptr->load_bytes_sec_stathandle, stat_annotate_str);
		}
	
	if (tcb_ptr->conn_id < load_packetsec_stat_dim_size)
		{
		/* Register statistics and raname them for easier collection. */
		tcb_ptr->tcp_conn_stat_ptr->load_packets_sec_stathandle = op_stat_reg ("TCP Connection.Load (packets/sec)", tcb_ptr->conn_id, OPC_STAT_LOCAL);
		op_stat_annotate (tcb_ptr->tcp_conn_stat_ptr->load_packets_sec_stathandle, stat_annotate_str);
		}

	FOUT;
	}


static void
tcp_mgr_rst_send (int seq_num, int ack, int ack_num, TcpT_Port local_port, InetT_Address orig_addr, 
	TcpT_Port orig_port, InetT_Address local_addr, OmsT_Dt_Key local_key, OmsT_Dt_Key remote_key)
	{
	Packet*				rst_pk_ptr;
	TcpT_Seg_Fields*	tcp_seg_fd_ptr;

	/** Respond to received packet with an RST. **/
	FIN (tcp_mgr_rst_send (seq_num, ack, ack_num, local_port, orig_addr, orig_port, local_addr, local_key, remote_key));

	/* Construct RST packet. */
	rst_pk_ptr = op_pk_create_fmt ("tcp_seg_v2");
	tcp_seg_fd_ptr = tcp_seg_fdstruct_create ();

	tcp_seg_fd_ptr->src_port 	= local_port;
	tcp_seg_fd_ptr->dest_port 	= orig_port;
	tcp_seg_fd_ptr->seq_num		= seq_num;
	tcp_seg_fd_ptr->flags		|= TCPC_FLAG_RST;
	tcp_seg_fd_ptr->data_len	= 0;
	
	/* Set the keys based on the keys in the received segment.	*/
	tcp_seg_fd_ptr->local_key  = local_key;
	tcp_seg_fd_ptr->remote_key = remote_key;

	if ((rst_pk_ptr == OPC_NIL) || (tcp_seg_fd_ptr == OPC_NIL))
		{
		op_prg_log_entry_write (ll_loghndl,
				"Error in function tcp_mgr_rst_send: unable to create or initialize RST segment.");
		FOUT;
		}

	if (ack)
		{
		/*	Set SEG.ACK and its number in RST segment.	*/
		tcp_seg_fd_ptr->flags	|= TCPC_FLAG_ACK;
		tcp_seg_fd_ptr->ack_num	= ack_num;
		}

	/* Set IP addressing information. */
	/* Note that the dest_addr and src_addr fields in	*/
	/* the ici are already set to the variables in		*/
	/* the ip_encap_ici_info structure. We just need to	*/
	/* set these variables accodingly.					*/

	/* No need to use inet_address_copy here because	*/
	/* these variables will be overwritten the next time*/
	/* a packet needs to be sent.						*/
	ip_encap_ici_info.dest_addr = orig_addr;
	ip_encap_ici_info.src_addr  = local_addr;

	/* Install the ici.									*/
	op_ici_install (ip_encap_ici_info.ip_encap_req_ici_ptr);

	/*	Set the structure field in the packet.			*/
	op_pk_nfd_set (rst_pk_ptr, "fields", tcp_seg_fd_ptr, tcp_seg_fdstruct_copy, tcp_seg_fdstruct_destroy, sizeof (TcpT_Seg_Fields));

	/* Generate trace information. */
	if (tcp_trace_active)
		tcp_seg_msg_print ("Sending -->", seq_num, ack_num, 0, tcp_seg_fd_ptr->flags);

	/* Send the segment. Use op_pk_send_forced becuause	*/
	/* We are reusing the Ici. Also the variables for	*/
	/* storing the destination or source might get		*/
	/* overwritten before ip_encap gets the packet.		*/
	op_pk_send_forced (rst_pk_ptr, TCPC_OUTSTRM_NETWORK);

	/* Uninstall the Ici.								*/
	op_ici_install (OPC_NIL);

	FOUT;
	}

static Compcode
tcp_mgr_port_availability_check (int requested_local_port)
	{
	TcpT_Tcb*           tcb_ptr = OPC_NIL;
    int                 index, list_size;
		
	/** Scan through the list of existing tcp connections and **/
	/** make sure that the requested port is not being used	  **/
	/** any of these connections.							  **/
	FIN (tcp_mgr_port_availability_check (requested_local_port));

	list_size = op_prg_list_size (tcb_list);
    for (index = 0; index < list_size; index++)
        {
        tcb_ptr = (TcpT_Tcb *) op_prg_list_access (tcb_list, index);
        if (tcb_ptr == OPC_NIL)
            op_prg_log_entry_write (ll_loghndl,
                    "Error in function tcp_tcb_from_addrs: unable to get TCB from list.");
        else if (requested_local_port == tcb_ptr->local_port)
            {
			/* This local port is already being used by another */
			/* connection. Return a faliure code, indicating 	*/
			/* the requested port is not available.				*/
            FRET (OPC_COMPCODE_FAILURE);
            }
        }

	/* We have completed the search and did not find any other 	*/
	/* tcp connection which was using this port. Indicate that 	*/
	/* the requested port is indeed available.					*/ 
    FRET (OPC_COMPCODE_SUCCESS);
	}

static int
tcp_mgr_next_avail_port_find (void)
	{
	TcpT_Tcb*           tcb_ptr = OPC_NIL; 
    int                 index, list_size; 
	int					temp_local_port;
	Boolean				port_found = OPC_FALSE;

	/** Scan through the list of tcp connections and identify an */
    /** unused local port number. This function is time consuming*/
    /** and is called only when the port numbers have wrapped    */
    /** around.                                                  */
	FIN (tcp_mgr_next_avail_port_find (void));
	
	/* Intialize the list size as the size of the tcp list		  */
	if (tcb_list != OPC_NIL)
		list_size = op_prg_list_size (tcb_list);
	
	/* Start by using the minimum available port number.	*/
	temp_local_port = TCPC_MIN_ASSIGNABLE_PORT;
		
	 while (!port_found)
		 {
         for (index = 0; index < list_size; index++)
			{
			tcb_ptr = (TcpT_Tcb *) op_prg_list_access (tcb_list, index);
        	if (tcb_ptr == OPC_NIL)
            	op_prg_log_entry_write (ll_loghndl,
                    "Error in function tcp_tcb_from_addrs: unable to get TCB from list.");
        	else if (temp_local_port == tcb_ptr->local_port)
            	{
            	/* This local port is already being used by another */
            	/* connection. Return a faliure code, indicating    */
            	/* the requested port is not available.             */
				break;
				}
			}

		if (index == list_size)
			{
			/* The temp port can be set as an available port	*/
			port_found = OPC_TRUE;
			FRET (temp_local_port);
			}
		else
			{
			/* We did not complete the sequential search as we 	*/
			/* came across a connection that is using the port	*/
			temp_local_port++;
			}
		
		/* Continue the search with the new port value.				*/
		if (temp_local_port == TCPC_MAX_ASSIGNABLE_PORT)
			{
			/* no available port 									*/
			temp_local_port = TCPC_NO_AVAIL_PORT;
			break; /* Out of while loop	*/
			} 
		}

	/* Return the local port value that has been computed.		*/
	FRET (temp_local_port);
	}					

static void
tcp_tcb_free (TcpT_Tcb* tcb_ptr)
	{
	/** This function free the TCP control block data structure **/
	FIN (tcp_tcb_free (tcb_ptr));
	
	/* Free the stat handle allocated to this control block */
	if (tcb_ptr->tcp_conn_stat_ptr != OPC_NIL) 
		{
		op_prg_mem_free (tcb_ptr->tcp_conn_stat_ptr);
		tcb_ptr->tcp_conn_stat_ptr = OPC_NIL;
		}
	
	/* Free the memory allocated to the InetT_Address fields.	*/
	inet_address_destroy (tcb_ptr->local_addr);
	inet_address_destroy (tcb_ptr->rem_addr);

	/* Free the data structure itself */
	op_prg_mem_free (tcb_ptr);
	
	FOUT;
	}


static Boolean
tcp_active_conn_count_reached (void)
	{
	int				index, list_size, active_conn_count = 0;
	TcpT_Tcb*		tcb_ptr;
	
	/** Find whether the number of allowed active TCP connections.	**/
	/** has been reached. An active	connection is a connection 		**/
	/** which remote port has been already specified.				**/
	FIN (tcp_active_conn_count_reached (void));
	
	/* Find the size of TC block list.	*/
	list_size = op_prg_list_size (tcb_list);
	
	for (index = 0; index < list_size; index++)
		{
		/* Get a block from the list.	*/
		tcb_ptr = (TcpT_Tcb*) op_prg_list_access (tcb_list, index);
				
		if (tcb_ptr->rem_port != TCPC_PORT_UNSPEC)
			{
			++active_conn_count;
			
			if (active_conn_count == max_connections)
				{
				/* Write a log message informing the user	*/
				/* that the sesion will not be opened.		*/
				if (num_sess_reach_log_written == OPC_FALSE)
					{
					tcp_max_number_sess_reached_log_write (max_connections);
					
					num_sess_reach_log_written = OPC_TRUE;
					}
				
				/* Update a statistic used to track number of		*/
				/* connections blocked due to limit being reached.	*/
				op_stat_write (blocked_conn_count_stathandle, (double) 1.0);
				
				/* Return status to indicate that connection limit	*/
				/* has been reached.								*/
				FRET (OPC_TRUE);
				}
			}
		}
			
	FRET (OPC_FALSE);
	}

	
/**** Error Handling functions. ****/
	
static void
tcp_mgr_error (const char* msg0)
    {
    /** Print an error message and exit the simulation. **/
	FIN (tcp_mgr_error (msg0));
 
    op_sim_end ("Error in TCP dispatch process (tcp_manager_v3):", msg0, OPC_NIL, OPC_NIL);

	FOUT;
    }

/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

#if defined (__cplusplus)
extern "C" {
#endif
	void tcp_manager_v3_dt (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_tcp_manager_v3_dt_init (int * init_block_ptr);
	VosT_Address _op_tcp_manager_v3_dt_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int);
	void _op_tcp_manager_v3_dt_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_tcp_manager_v3_dt_terminate (OP_SIM_CONTEXT_ARG_OPT);
	void _op_tcp_manager_v3_dt_svar (void *, const char *, void **);


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, unsigned int _op_size);
	VosT_Address Vos_Alloc_Object_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Address _op_ob_ptr);
#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
tcp_manager_v3_dt (OP_SIM_CONTEXT_ARG_OPT)
	{

#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (tcp_manager_v3_dt ());
		{
		/* Temporary Variables */
		int					intrpt_type = OPC_INT_UNDEF;
		int					intrpt_strm = OPC_INT_UNDEF;
		int					intrpt_code = OPC_INT_UNDEF;
		Ici*				ici_ptr = OPC_NIL;
		Ici*				intf_ici_ptr = OPC_NIL;
		Objid				strm_objid = OPC_OBJID_INVALID;
		
		int					higher_layer_protocol_type;
		
		List*				proc_record_handle_list_ptr;
		int					record_handle_list_size;
		OmsT_Pr_Handle		proc_record_handle;
		double				server_id;
		
		TcpT_Conn_Id		conn_id;
		TcpT_Port			local_port;
		OmsT_Dt_Key			local_key = OmsC_Dt_Key_Undefined;
		OmsT_Dt_Key			remote_key = OmsC_Dt_Key_Undefined;
		
		InetT_Address		rem_addr;
		InetT_Address		local_addr;
		InetT_Address*		addr_ptr;
		Boolean				inet_support;
		char				rem_addr_str [IPC_ADDR_STR_LEN];
		char				local_addr_str [IPC_ADDR_STR_LEN];
		int					type_of_service;
		
		TcpT_Port			rem_port;
		int					strm_index;
		int					urgent;
		
		int					list_size;
		int					i;
		
		TcpT_Tcb*			tcb_ptr = OPC_NIL;
		TcpT_Tcb*			test_tcb_ptr;
		int					seg_ack = 0;
		int					seg_seq;
		int					seg_len;
		
		char				msg0 [512], msg1 [512], msg2 [512];
		int					status;
		
		static int			ev_defined = OPC_FALSE;
		static Pmohandle	ev_pmh;
		static int			tcb_defined = OPC_FALSE;
		static Pmohandle	tcb_pmh;
		
		int					ctr;
		char				scratch_str [512];
		char				scratch_str1 [512];
		int					my_node_id, my_subnet_id;
		
		double				pk_size;
		double				byte_load;
		
		Boolean				conn_failed = OPC_FALSE;
		Boolean				low_level_error = OPC_FALSE;
		Evhandle			abort_evh;
		
		TcpT_Seg_Fields*	pk_fd_ptr;
		char                previous_state [16];
		Boolean				invoke_child_process;
		/* End of Temporary Variables */


		FSM_ENTER ("tcp_manager_v3_dt")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (active) enter executives **/
			FSM_STATE_ENTER_UNFORCED (0, "active", state0_enter_exec, "tcp_manager_v3_dt [active enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [active enter execs]", state0_enter_exec)
				{
				/* Clear the event record. */
				ev_ptr->event = TCPC_EV_NONE;
				ev_ptr->pk_ptr = OPC_NIL;
				ev_ptr->flags = 0;
				ev_ptr->num_pks = 0;
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"tcp_manager_v3_dt")


			/** state (active) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "active", "tcp_manager_v3_dt [active exit execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [active exit execs]", state0_exit_exec)
				{
				/* Determine the interrupt type as the model perform .	*/
				intrpt_type = op_intrpt_type ();
				
				switch (intrpt_type)
					{
					case (OPC_INTRPT_ENDSIM):
						{
						/* determine whether diagnostic printing will be performed */
						if (print_conn_info)
							{
							/* Print out connection statistic information */
							printf ("\n\n");
				
							/* Print the title for the connection information table. */
							my_node_id = own_node_objid;
							my_subnet_id = op_topo_parent (my_node_id);
							op_ima_obj_attr_get (my_node_id, "name", scratch_str);
							op_ima_obj_attr_get (my_subnet_id, "name", scratch_str1);
				
							printf ("\t\t\t\tTCP Connection Information\n");
							printf ("\t\t\t\t==========================\n\n");
							printf ("\t\t\t\t     Node: \"%s\"\n", scratch_str);
							printf ("\t\t\t\t   Subnet: \"%s\"\n\n", scratch_str1);
				
							printf ("\t%8s %8s %17s %6s %6s %10s %10s\n", 
								"--------", "--------", "-----------------", "------", "------", "----------", "----------");
							printf ("\t%8s %8s %17s %6s %6s %10s %10s\n", 
								"  Conn  ", "  Conn  ", "    Remote IP    ", " Rem. ", " Local", "   Start  ", "   End    ");
							printf ("\t%8s %8s %17s %6s %6s %10s %10s\n", 
								"   ID   ", "  Type  ", "     Address     ", " Port ", " Port ", "   Time   ", "   Time   ");
							printf ("\t%8s %8s %17s %6s %6s %10s %10s\n", 
								"--------", "--------", "-----------------", "------", "------", "----------", "----------");
				
							for (ctr = 1; ctr < CONNECTION_STATISTIC_COUNT; ctr++)
								{
								if (diag_ptr[ctr].tcp_conn_id != CONN_NOT_USED)
									{
									if (diag_ptr[ctr].end_time <= 0.0)
										{
										if (! inet_address_valid (diag_ptr[ctr].tcp_rem_addr))
											{
											printf ("\t   %-2d    %-7s  %-15s   %-5s  %-5d  %8s   %8s\n", 
												diag_ptr[ctr].tcp_conn_id, " PASSIVE", "N/A", "N/A", 
												diag_ptr[ctr].tcp_local_port , "N/A", "N/A");
											}
										else
											{
											inet_address_print (diag_ptr[ctr].tcp_rem_addr_str, diag_ptr[ctr].tcp_rem_addr);
											printf ("\t   %-2d    %-7s   %-15s   %-5d  %-5d  %8.1f   %8s\n", 
												diag_ptr[ctr].tcp_conn_id, " ACTIVE", diag_ptr[ctr].tcp_rem_addr_str,  
												diag_ptr[ctr].tcp_rem_port, diag_ptr[ctr].tcp_local_port, 
												diag_ptr[ctr].start_time, "N/A");
											}
										}
									else
										{
										if (diag_ptr[ctr].tcp_local_port != 0)
											{
											if (! inet_address_valid (diag_ptr[ctr].tcp_rem_addr))
												{
												printf ("\t   %-3s   %-7s  %-15s   %-5d  %-5d  %8.1f   %8.1f\n", 
													"N/A", " PASSIVE", "N/A", "N/A", diag_ptr[ctr].tcp_local_port, 
													diag_ptr[ctr].start_time, diag_ptr[ctr].end_time);
												}
											else
												{
												inet_address_print (diag_ptr[ctr].tcp_rem_addr_str, diag_ptr[ctr].tcp_rem_addr);
												printf ("\t   %-2d    %-7s   %-15s   %-5d  %-5d  %8.1f   %8.1f\n", 
													diag_ptr[ctr].tcp_conn_id, " ACTIVE", diag_ptr[ctr].tcp_rem_addr_str, 
													diag_ptr[ctr].tcp_rem_port, diag_ptr[ctr].tcp_local_port, 
													diag_ptr[ctr].start_time, diag_ptr[ctr].end_time);
												}
											}
										}
									}
				
								/*	Deallocate the memory allocated for the remote IP address.	*/
								inet_address_destroy (diag_ptr[ctr].tcp_rem_addr);
								}
				
							printf ("\t%8s %8s %17s %6s %6s %10s %10s\n", 
								"--------", "--------", "-----------------", "------", "------", "----------", "----------");
							}
						break;
						}
					case (OPC_INTRPT_FAIL):
						{
						if (op_intrpt_source () == own_node_objid)
							{
							if (tcp_parameter_ptr->node_failed == OPC_FALSE)
								tcp_parameter_ptr->node_failed = OPC_TRUE;
							}
						break;
						}
					case (OPC_INTRPT_RECOVER):
						{
						if (op_intrpt_source () == own_node_objid)
							{
							if (tcp_parameter_ptr->node_failed == OPC_TRUE)
								tcp_parameter_ptr->node_failed = OPC_FALSE;
							}
						break;
						}
					default:
						{
						tcp_trace_active = op_prg_odb_ltrace_active ("tcp");
				
						if (intrpt_type == OPC_INTRPT_STRM)
							intrpt_strm = op_intrpt_strm ();
						else
							intrpt_code = op_intrpt_code ();
				
						/* Obtain the interface control information associated with	*/
						/* this interrupt.											*/
						ici_ptr = op_intrpt_ici ();
				
						/*	If the ICI could not be obtained, generate a warning and continue.	*/
						if (ici_ptr == OPC_NIL)
							{
							op_prg_log_entry_write (ll_loghndl, 
								"Unable to obtain ICI associated with interrupt of type: %d", 
								intrpt_type);
							}
						break;
						}
						}
				   
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (active) transition processing **/
			FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [active trans conditions]", state0_trans_conds)
			FSM_INIT_COND (OPEN)
			FSM_TEST_COND (SEND)
			FSM_TEST_COND (RECEIVE)
			FSM_TEST_COND (CLOSE)
			FSM_TEST_COND (ABORT)
			FSM_TEST_COND (SEG_ARRIVAL)
			FSM_TEST_COND (STATUS_IND)
			FSM_TEST_COND (END_SIM)
			FSM_TEST_COND (FAILURE_RECOVERY)
			FSM_TEST_LOGIC ("active")
			FSM_PROFILE_SECTION_OUT (state0_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 1, state1_enter_exec, ;, "OPEN", "", "active", "OPEN", "tcp_manager_v3_dt [active -> OPEN : OPEN / ]")
				FSM_CASE_TRANSIT (1, 2, state2_enter_exec, ;, "SEND", "", "active", "SEND", "tcp_manager_v3_dt [active -> SEND : SEND / ]")
				FSM_CASE_TRANSIT (2, 3, state3_enter_exec, ;, "RECEIVE", "", "active", "RECEIVE", "tcp_manager_v3_dt [active -> RECEIVE : RECEIVE / ]")
				FSM_CASE_TRANSIT (3, 4, state4_enter_exec, ;, "CLOSE", "", "active", "CLOSE", "tcp_manager_v3_dt [active -> CLOSE : CLOSE / ]")
				FSM_CASE_TRANSIT (4, 5, state5_enter_exec, ;, "ABORT", "", "active", "ABORT", "tcp_manager_v3_dt [active -> ABORT : ABORT / ]")
				FSM_CASE_TRANSIT (5, 6, state6_enter_exec, ;, "SEG_ARRIVAL", "", "active", "SEG_RCV", "tcp_manager_v3_dt [active -> SEG_RCV : SEG_ARRIVAL / ]")
				FSM_CASE_TRANSIT (6, 7, state7_enter_exec, ;, "STATUS_IND", "", "active", "STATUS", "tcp_manager_v3_dt [active -> STATUS : STATUS_IND / ]")
				FSM_CASE_TRANSIT (7, 0, state0_enter_exec, ;, "END_SIM", "", "active", "active", "tcp_manager_v3_dt [active -> active : END_SIM / ]")
				FSM_CASE_TRANSIT (8, 0, state0_enter_exec, ;, "FAILURE_RECOVERY", "", "active", "active", "tcp_manager_v3_dt [active -> active : FAILURE_RECOVERY / ]")
				}
				/*---------------------------------------------------------*/



			/** state (OPEN) enter executives **/
			FSM_STATE_ENTER_FORCED (1, "OPEN", state1_enter_exec, "tcp_manager_v3_dt [OPEN enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [OPEN enter execs]", state1_enter_exec)
				{
				/* Read the arguments to the OPEN call. */
				if ((op_ici_attr_get (ici_ptr, "conn_id",    		&conn_id)    == OPC_COMPCODE_FAILURE) ||
					(op_ici_attr_get (ici_ptr, "local_port", 		&local_port) == OPC_COMPCODE_FAILURE) ||
					(op_ici_attr_get (ici_ptr, "strm_index", 		&strm_index) == OPC_COMPCODE_FAILURE) ||
					(op_ici_attr_get (ici_ptr, "rem_port",   		&rem_port)   == OPC_COMPCODE_FAILURE) ||
					(op_ici_attr_get (ici_ptr, "inet_support", 		&inet_support)		== OPC_COMPCODE_FAILURE) ||
					(op_ici_attr_get (ici_ptr, "Type of Service",   &type_of_service)   == OPC_COMPCODE_FAILURE))
					{
					conn_failed = OPC_TRUE;
					op_prg_log_entry_write (ll_loghndl, "TCP OPEN failed - unable to obtain attributes from OPEN command ICI.");
					}
				
				/* Read  in the address fields from the ici.		*/
				if (op_ici_attr_get (ici_ptr, "rem_addr", &addr_ptr) == OPC_COMPCODE_FAILURE)
					{
					conn_failed = OPC_TRUE;
					op_prg_log_entry_write (ll_loghndl, "TCP OPEN failed - unable to obtain attributes from OPEN command ICI.");
					}
				
				/* Store the remote address locally.											*/
				rem_addr = *addr_ptr;
				
				if (op_ici_attr_get (ici_ptr, "local_addr", &addr_ptr) == OPC_COMPCODE_FAILURE)
					{
					conn_failed = OPC_TRUE;
					op_prg_log_entry_write (ll_loghndl, "TCP OPEN failed - unable to obtain attributes from OPEN command ICI.");
					}
				
				/* Store the local address locally. Note that if the source address is not		*/
				/* explicitly specified, the field will be set to NIL.							*/
				if (OPC_NIL == addr_ptr)
					{
					local_addr = INETC_ADDRESS_INVALID;
					}
				else
					{
					local_addr = *addr_ptr;
					}
				
				/* First make sure that the maximum number of TCP Connections has not been reached.	*/
				if ((rem_port != TCPC_PORT_UNSPEC) && (max_connections != OPC_INT_INFINITY) && (tcp_active_conn_count_reached () == OPC_TRUE))
					{
					/* Maximum number of TCP connections has been reached.			*/
					/* Note that we always allow passive connection to be opened.	*/	
						
					/* Inform the application that the connection was not opened.	*/
					if (op_ici_attr_set (ici_ptr, "conn_id", TCPC_CONN_ID_INVALID) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl, 
								"TCP OPEN failed - unable to set connection id in command ICI.");
					
					if (tcp_trace_active)
						{
						op_prg_odb_print_major (
								"TCP process was unable to open a new connection.\n", 
								"The Active Connections Threshold has been exceeded.\n", OPC_NIL);
						}
					}
				else
					{
					/* Connection threshold has not been exceeded or we are opening a passive connection.	*/ 
				
					/* If no stream index has been specified, pick a logical one. */
					if ((strm_index == TCPC_STRM_INDEX_UNSPEC) && (conn_failed == OPC_FALSE))
						{
						strm_objid = op_topo_connect (own_mod_objid, op_intrpt_source (), OPC_OBJTYPE_STRM, 0);
							if (strm_objid == OPC_OBJID_INVALID)
								{
								tcp_no_stream_log_write ();
								conn_failed = OPC_TRUE;
								}
						else
							{
							if (op_ima_obj_attr_get (strm_objid, "src stream", &strm_index) == OPC_COMPCODE_FAILURE)
								{
								op_prg_log_entry_write (ll_loghndl, 
									"TCP OPEN failed - unable to get source stream attribute from stream object.");
								conn_failed = OPC_TRUE;
								}
							if (op_ici_attr_set (ici_ptr, "strm_index", strm_index) == OPC_COMPCODE_FAILURE)
								{
								op_prg_log_entry_write (ll_loghndl, 
									"TCP OPEN failed - unable to set stream index in command ICI.");
								conn_failed = OPC_TRUE;
								}
							}
						}
				
					/* Initialize a flag setting that a created child process should be invoked.	*/
					invoke_child_process = OPC_TRUE;
				
					/* Find the preexisting TCB for this connection, if any.	*/
					/* If none exists, and the connection id is unspecified,	*/
					/* create a new TCB and add it to the list.					*/
					if (conn_id == TCPC_CONN_ID_UNSPEC && conn_failed == OPC_FALSE)
						{
						if (local_port == TCPC_PORT_UNSPEC)
							{
							/* Must specify the local port to open a new connection. */
							inet_address_print (rem_addr_str, rem_addr);
							tcp_local_port_log_write (local_port, rem_port, rem_addr_str);
							tcb_ptr = OPC_NIL;
							}
				
						else if ((local_port > TCPC_MIN_ASSIGNABLE_PORT) &&
								(local_port < *local_port_ptr) &&
								(port_values_wrapped_around == OPC_FALSE) &&
								(tcp_mgr_port_availability_check (local_port) != OPC_COMPCODE_SUCCESS))
							{
							/* The application is attempting to use a port that */
							/* is lower than the currently available port and 	*/
							/* the requested port number is unavailable. Write 	*/
							/* out a log indicating that the connection will 	*/
							/* not be created. 									*/
							op_prg_log_entry_write (ll_loghndl, 
									"TCP OPEN failed - Port is already in use.");
							}
						else if (rem_port == TCPC_PORT_UNSPEC && (intrpt_code == TCPC_COMMAND_OPEN_ACTIVE) &&
							tcp_tcb_from_addrs (tcp_dt_handle, tcb_list, ll_loghndl, OmsC_Dt_Key_Undefined,
												OmsC_Dt_Key_Undefined, local_port, rem_addr, rem_port) != OPC_NIL)
				
							{
							/* A connection with the given specifications already	*/
							/* exists.  Do not attempt to open another one.			*/
							inet_address_print (rem_addr_str, rem_addr);
							tcp_dup_spec_log_write (local_port, rem_port, rem_addr_str);
							tcb_ptr = OPC_NIL;
							}
					
						else		
							{
							/* Open a new connection. However, first make sure that there is no	*/
							/* existing passive connection for the same port. This can happen 	*/
							/* if a previous connection for the same port was closed using 		*/
							/* passive reset. When a conenction is closed using passive reset, 	*/
							/* the connection processs is not destroyed (as is the case for 	*/
							/* other reasons), but stays open. In that case there is a free 	*/
							/* connection process that can be now used. 						*/
							if (rem_port == TCPC_PORT_UNSPEC)
								{
								/** Remote port is not specified. This is a new passive session.	**/
							
								/* Find whether there is a passive connection that can be used.	*/
								/* Such a connection will be in a "LISTEN" state.				*/
								tcb_ptr = tcp_tcb_listen_state_from_addrs (tcp_dt_handle, tcb_list, ll_loghndl,
									OmsC_Dt_Key_Undefined, OmsC_Dt_Key_Undefined, local_port, rem_addr, rem_port);
							
								if (tcb_ptr != OPC_NIL)
									{
									/* There is a connection process that can be used.	*/
								
									/* Bind this one.	*/
									
									/* Set its connection ID.	*/
									tcb_ptr->conn_id = conn_id_new++;
							
									/* Return the connection ID to the application. 								*/
									/* Application will be referring to this conenction using this connection ID.	*/
									if (op_ici_attr_set (ici_ptr, "conn_id", tcb_ptr->conn_id) == OPC_COMPCODE_FAILURE)
										{
										op_prg_log_entry_write (ll_loghndl, 
											"TCP OPEN failed - unable to set connection ID in TCP command ICI.");
										conn_failed = OPC_TRUE;
										}
							                                
									/* Return the hash table key in the ICI */
									if (op_ici_attr_set (ici_ptr, "local_key", tcb_ptr->local_key) == OPC_COMPCODE_FAILURE)
										{
										op_prg_log_entry_write (ll_loghndl, 
				                                        "TCP OPEN failed - unable to set local_key in TCP command ICI.");
										conn_failed = OPC_TRUE;
										}
									
									/* Set the stream index.	*/
									tcb_ptr->strm_index = strm_index;
				
									if (conn_failed == OPC_FALSE)
										{
										/* There is no need to invoke child process to allow it initialize its SVs.	*/
										invoke_child_process = OPC_FALSE;
				
										/* Initialize diagnostic structure */
										if (tcb_ptr->conn_id < CONNECTION_STATISTIC_COUNT)
											{
											/*	De-allocate the memory allocated to	*/
											/*	the original data structure element	*/
											/*	to contain the remote IP address.	*/
											inet_address_destroy (diag_ptr[tcb_ptr->conn_id].tcp_rem_addr);
					
											/*	Assign appropriate values to other	*/
											/*	elements of the diag structure.		*/
											diag_ptr[tcb_ptr->conn_id].tcp_conn_id    = tcb_ptr->conn_id;
											diag_ptr[tcb_ptr->conn_id].tcp_local_port = tcb_ptr->local_port;
											diag_ptr[tcb_ptr->conn_id].tcp_rem_addr   = inet_address_copy (tcb_ptr->rem_addr);
											diag_ptr[tcb_ptr->conn_id].tcp_rem_port   = tcb_ptr->rem_port;
											diag_ptr[tcb_ptr->conn_id].start_time     = op_sim_time ();
											}
										}
									}
								}
								
							if (invoke_child_process == OPC_TRUE)
								{
								/* This is a completely new connection.		*/
								/* Create a new TCB and add it to the list. */
				
								/* First, define the pooled memory obejct for tcb's, if not already done. */
								if (tcb_defined == OPC_FALSE)
									{
									tcb_defined = OPC_TRUE;
									tcb_pmh = op_prg_pmo_define ("TCP Connection Block", sizeof (TcpT_Tcb), 32);
									}
				
								/* Allocate a new TCP control block.	*/
								tcb_ptr = (TcpT_Tcb *) op_prg_pmo_alloc (tcb_pmh);
								if (tcb_ptr == OPC_NIL)
									{
									op_prg_log_entry_write (ll_loghndl, 
										"During TCP OPEN, unable to allocate memory for TCB structure.");
									op_sim_end ("Please check simulation log for simulation kernel errors.", "", "", "");
									}
								strcpy (tcb_ptr->state_name, "OPEN");
								tcb_ptr->conn_id = conn_id_new++;
				
								/* Install this TCB in the dispatch table. The returned	*/
								/* key will be used for dereferencing this TCB later.	*/
								tcb_ptr->dt_handle  = tcp_dt_handle;
								tcb_ptr->local_key  = oms_dt_item_insert (tcp_dt_handle, tcb_ptr);
								tcb_ptr->remote_key = OmsC_Dt_Key_Undefined;
				
								/* Initialize ECN status.	*/
								tcb_ptr->ecn_status = TcpC_Ecn_Not_Supported;
							
								/* Set LAN related information in the TCB.	*/
								tcb_ptr->lan_handle    = my_lanhandle;
								tcb_ptr->lan_server_id = lan_server_identifier;
								
								/* The next available port pointer is used by the TCP 	*/
								/* API package to identify an available local port 	  	*/
								/* number for creating a connection. Before updating  	*/
								/* the next available port make sure that the local   	*/
								/* port is not a reserved port number and the value	  	*/
								/* is greater than the last computer next avail port. 	*/
								/* Some connections might tend to use a value without 	*/
								/* checking if the local port is available, it is not 	*/
								/* fair to use this data to compute the next available	*/
								/* port.											  	*/
								if (port_values_wrapped_around == OPC_FALSE)
									{
									if (local_port >= TCPC_MIN_ASSIGNABLE_PORT && local_port >= *local_port_ptr)
										{
										*local_port_ptr = local_port+1;
										}
				
									/* If the local port has gone over the max available 	*/
									/* port numbers, we have to wrap around to set the next	*/
									/* available port value.								*/
									if (*local_port_ptr == TCPC_MAX_ASSIGNABLE_PORT)
										{
										/* Set the indication that we have already used up  */
										/* all the available port numbers. The next move is */
										/* to wrap around and start from the minimum usable */
										/* port number. From now on we cannot simply assign */
										/* the next available port as current_port+1 as the */
										/* the port current_port+1 could still be in use.   */
										port_values_wrapped_around = OPC_TRUE;
										}
									}
				
								/* The local port values have already wrapped around. A	*/
								/* sequential search for the next available port is now	*/
								/* required.											*/
								else
									{
									*local_port_ptr = tcp_mgr_next_avail_port_find ();
									}
				
								tcb_ptr->strm_index = strm_index;
								tcb_ptr->local_port = local_port;
								tcb_ptr->rem_addr = inet_address_copy (rem_addr);
								tcb_ptr->rem_port = rem_port;
								tcb_ptr->type_of_service = type_of_service;
								tcb_ptr->inet_support = inet_support;
				
								/* In case of open request for a active connection, update  */
								/* the active connection related variables                  */
								if (intrpt_code == TCPC_COMMAND_OPEN_ACTIVE)
									{
									/* Write the updated active connection stats.           */
									op_stat_write (active_conn_handle, (double)(1.0));
								
									/* For active open sessions all the information about the	*/
									/* connection available so rename the per connection TCP	*/
									/* statistics (dimensioned) to a more explicable name. For	*/
									/* passive sessions that get converted to active sessions,	*/
									/* the remote address is not yet available - they perform	*/
									/* this registration when a SYN is received.				*/
									/* Registers all statistics maintained by this connection.	*/
									tcp_connection_based_statistics_register (tcb_ptr, OPC_TRUE);
									}
							
								/* Just initialize the local address for now. If it was */
								/* not set, set it to an invalid value. It will be 		*/
								/* filled later with the correct value.					*/
								tcb_ptr->local_addr = inet_address_copy (local_addr);
						
								/*	Assign appropriate values to the elements	*/
								/*	of the Transmission Control Block (tcb)		*/
								tcb_ptr->app_objid = op_intrpt_source ();
								if (tcb_ptr->app_objid == OPC_OBJID_INVALID)
									{
									op_prg_log_entry_write (ll_loghndl, 
										"TCP OPEN failed - unable to determine source of OPEN (remote) interrupt.");
									conn_failed = OPC_TRUE;
									}
								else
									{
									op_prg_list_insert (tcb_list, tcb_ptr, OPC_LISTPOS_TAIL);
				
									/* Return the connection ID to the application. */
									if (op_ici_attr_set (ici_ptr, "conn_id", tcb_ptr->conn_id) == OPC_COMPCODE_FAILURE)
										{
										op_prg_log_entry_write (ll_loghndl, 
											"TCP OPEN failed - unable to set connection ID in TCP command ICI.");
										conn_failed = OPC_TRUE;
										}
							                                
									/* Return the hash table key in the ICI */
									if (op_ici_attr_set (ici_ptr, "local_key", tcb_ptr->local_key) == OPC_COMPCODE_FAILURE)
										{
										op_prg_log_entry_write (ll_loghndl, 
											"TCP OPEN failed - unable to set local_key in TCP command ICI.");
										conn_failed = OPC_TRUE;
										}
							 
									}
				
								if (conn_failed == OPC_FALSE)
									{
									/* Initialize diagnostic structure */
									if (tcb_ptr->conn_id < CONNECTION_STATISTIC_COUNT)
										{
										/*	De-allocate the memory allocated to	*/
										/*	the original data structure element	*/
										/*	to contain the remote IP address.	*/
										inet_address_destroy (diag_ptr[tcb_ptr->conn_id].tcp_rem_addr);
					
										/*	Assign appropriate values to other	*/
										/*	elements of the diag structure.		*/
										diag_ptr[tcb_ptr->conn_id].tcp_conn_id    = tcb_ptr->conn_id;
										diag_ptr[tcb_ptr->conn_id].tcp_local_port = tcb_ptr->local_port;
										diag_ptr[tcb_ptr->conn_id].tcp_rem_addr   = inet_address_copy (tcb_ptr->rem_addr);
										diag_ptr[tcb_ptr->conn_id].tcp_rem_port   = tcb_ptr->rem_port;
										diag_ptr[tcb_ptr->conn_id].start_time     = op_sim_time ();
										}
									}
								}
							}
						}
				
					else
						{
						tcb_ptr = tcp_tcb_from_id (tcp_dt_handle, conn_id, OmsC_Dt_Key_Undefined);
				 
						tcp_open_existing_log_write (conn_id);
						}
				
					if (tcb_ptr == OPC_NIL)
						{
						conn_failed = OPC_TRUE;
						if (tcp_trace_active)
							op_prg_odb_print_minor ("Connection not opened.", OPC_NIL);
						tcp_open_failed_log_write ();
						if (op_ici_attr_set (ici_ptr, "conn_id", TCPC_CONN_ID_INVALID) == OPC_COMPCODE_FAILURE)
							op_prg_log_entry_write (ll_loghndl, 
								"TCP OPEN was unable to reset connection ID in command ICI for invalid command.");
						}
					else 
						{
						/* Previously unspecified socket information may have	*/
						/* been newly specified.  Check for unspecified data.	*/
						if (tcb_ptr->rem_port == TCPC_PORT_UNSPEC)
							tcb_ptr->rem_port = rem_port;
						if (! inet_address_valid (tcb_ptr->rem_addr))
							tcb_ptr->rem_addr = inet_address_copy (rem_addr);
				
						/* Send the OPEN command to the connection process. */
						if (intrpt_code == TCPC_COMMAND_OPEN_ACTIVE)
							ev_ptr->event = TCPC_EV_OPEN_ACTIVE;
						else
							ev_ptr->event = TCPC_EV_OPEN_PASSIVE;
					
						/*	Active open requests must specify remote IP address.	*/
						if ((ev_ptr->event == TCPC_EV_OPEN_ACTIVE) &&
							(! inet_address_valid (tcb_ptr->rem_addr)))
							{
							conn_failed = OPC_TRUE;
							tcp_no_rem_addr_log_write ();
							}
						else
							{
							/* Assign tcb & tcp_conn_info to the encompassing structure	*/
							tcp_ptc_mem.tcb_info_ptr = tcb_ptr;
							tcp_ptc_mem.tcp_conn_params_ptr = tcp_parameter_ptr;
						
							if (invoke_child_process == OPC_TRUE)
								{
								/* Create and invoke the connection process.	*/
								tcb_ptr->conn_pro = op_pro_create ("tcp_conn_v3_dt", &tcp_ptc_mem);
								if (op_pro_valid (tcb_ptr->conn_pro) == OPC_FALSE)
									{
									op_prg_log_entry_write (ll_loghndl, 
										"TCP OPEN failed - unable to create dynamic connection process.");
									conn_failed = OPC_TRUE;
									}
									else if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
										op_prg_log_entry_write (ll_loghndl, 
											"Connection process was not invoked to handle TCP OPEN command - invocation failed.");
									}
							}
						}
				
					/* If the connection open failed, then deallocate the memory allocated	*/
					/* to the transmisison control block, else, register statistics for		*/
					/* this newly opened TCP connection.									*/
					if (conn_failed == OPC_TRUE)
						{
						/* Clean up the TCB for this failed connection, including the TCB.  */
						if (tcb_ptr != OPC_NIL)
							{
							test_tcb_ptr = (TcpT_Tcb *)op_prg_list_access (tcb_list, OPC_LISTPOS_TAIL);
							if (test_tcb_ptr == tcb_ptr)
								tcb_ptr = (TcpT_Tcb *)op_prg_list_remove (tcb_list, OPC_LISTPOS_TAIL);
							tcp_tcb_free (tcb_ptr);
							}
						}
					}
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** state (OPEN) exit executives **/
			FSM_STATE_EXIT_FORCED (1, "OPEN", "tcp_manager_v3_dt [OPEN exit execs]")


			/** state (OPEN) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "OPEN", "active", "tcp_manager_v3_dt [OPEN -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (SEND) enter executives **/
			FSM_STATE_ENTER_FORCED (2, "SEND", state2_enter_exec, "tcp_manager_v3_dt [SEND enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [SEND enter execs]", state2_enter_exec)
				{
				if (op_ici_attr_get (ici_ptr, "conn_id", &conn_id) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to get connection ID from command ICI.");
				                                
				if (op_ici_attr_get (ici_ptr, "local_key", &local_key) == OPC_COMPCODE_FAILURE)
				    op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to get local_key from command ICI.");
				                                
				tcb_ptr = tcp_tcb_from_id (tcp_dt_handle, conn_id, local_key);
				
				ev_ptr->event = TCPC_EV_SEND;
				ev_ptr->pk_ptr = op_pk_get (intrpt_strm);
				if (ev_ptr->pk_ptr == OPC_NIL)
					{
					tcb_ptr = OPC_NIL;
					op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to get packet from input stream.");
					}
				 
				if (tcb_ptr != OPC_NIL)
					{
					/*	Calculate Statistics. In the model code (below), we	*/
					/*	will record the "<units>/sec" statistic in <units>	*/
					/*	where <units> can be "byte" or "packets". OPNET's	*/
					/*	statistics "capture mode" feature will be used to	*/
					/*	record it in <units>/sec.							*/ 
					pk_size = (double) op_pk_total_size_get (ev_ptr->pk_ptr);
					byte_load = (pk_size / 8.0);
				
					/* Write Stats */
					op_stat_write (byte_load_handle,   byte_load);
					op_stat_write (packet_load_handle, 1.0);
				
					op_stat_write (byte_sec_load_handle,   byte_load);
					op_stat_write (packet_sec_load_handle, 1.0);
				
					/* Record extra data-points to enable proper computation of		*/
					/* the "sum/time" based statistics.								*/
					op_stat_write (byte_sec_load_handle,   0.0);
					op_stat_write (packet_sec_load_handle, 0.0);
				
					/* Write per connection statistics */
					if (tcb_ptr->tcp_conn_stat_ptr != OPC_NIL)
						{
						if (op_stat_valid (tcb_ptr->tcp_conn_stat_ptr->load_bytes_stathandle))
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_bytes_stathandle, byte_load);
						
						if (op_stat_valid (tcb_ptr->tcp_conn_stat_ptr->load_packets_stathandle))
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_packets_stathandle, 1.0);
						
						if (op_stat_valid (tcb_ptr->tcp_conn_stat_ptr->load_bytes_sec_stathandle))
							{
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_bytes_sec_stathandle, byte_load);
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_bytes_sec_stathandle, 0.0);
							}
						
						if (op_stat_valid (tcb_ptr->tcp_conn_stat_ptr->load_packets_sec_stathandle))
							{
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_packets_sec_stathandle, 1.0);
							op_stat_write (tcb_ptr->tcp_conn_stat_ptr->load_packets_sec_stathandle, 0.0);
							}
						}
				
					/* Set flags for the outgoing packet. */
					ev_ptr->flags = TCPC_FLAG_NONE;
					if (op_ici_attr_get (ici_ptr, "urgent", &urgent) == OPC_COMPCODE_FAILURE)
						{
						urgent = 0;
						op_prg_log_entry_write (ll_loghndl, 
								"In TCP SEND, failed to get urgent flag from command ICI.");
						}
					else if (urgent)
						ev_ptr->flags |= TCPC_FLAG_URG;
				
					if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to invoke connection process.");
					}
				else
					{
					/* Destroy the packet.	*/
					op_pk_destroy (ev_ptr->pk_ptr);
					
					if (tcp_trace_active)
						{
						sprintf (msg0, "SEND command issued to invalid connection (%d)", conn_id);
						op_prg_odb_print_major (msg0, OPC_NIL);
						}
				
					tcp_invalid_conn_log_write (conn_id, "SEND");
					if (op_ici_attr_set (ici_ptr, "conn_id", TCPC_CONN_ID_INVALID) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl, 
								"TCP SEND was unable to reset connection ID in command ICI for invalid connection.");
					}
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** state (SEND) exit executives **/
			FSM_STATE_EXIT_FORCED (2, "SEND", "tcp_manager_v3_dt [SEND exit execs]")


			/** state (SEND) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "SEND", "active", "tcp_manager_v3_dt [SEND -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (RECEIVE) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "RECEIVE", state3_enter_exec, "tcp_manager_v3_dt [RECEIVE enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [RECEIVE enter execs]", state3_enter_exec)
				{
				if (op_ici_attr_get (ici_ptr, "conn_id", &conn_id) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl,
							"TCP RECEIVE failed - unable to get connection ID from command ICI.");
				                                
				if (op_ici_attr_get (ici_ptr, "local_key", &local_key) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to get local_key from command ICI.");
				                                
				tcb_ptr = tcp_tcb_from_id (tcp_dt_handle, conn_id, local_key);
				 
				if (tcb_ptr != OPC_NIL)
					{
					ev_ptr->event = TCPC_EV_RECEIVE;
					if (op_ici_attr_get (ici_ptr, "num_pks", &ev_ptr->num_pks) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
							"TCP RECEIVE failed - unable to get command argument from command ICI.");
					else
						{
						if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
							"TCP RECEIVE failed - unable to invoke TCP socket process.");
						}
					}
				else
					{
					if (tcp_trace_active)
						{
						sprintf (msg0, "RECEIVE command issued to invalid connection (%d)", conn_id);
						op_prg_odb_print_major (msg0, OPC_NIL);
						}		
					tcp_invalid_conn_log_write (conn_id, "RECEIVE");
				
					if (op_ici_attr_set (ici_ptr, "conn_id", TCPC_CONN_ID_INVALID) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
								"TCP RECEIVE was unable to reset connection ID in command ICI for invalid connection.");
					}
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (RECEIVE) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "RECEIVE", "tcp_manager_v3_dt [RECEIVE exit execs]")


			/** state (RECEIVE) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "RECEIVE", "active", "tcp_manager_v3_dt [RECEIVE -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (CLOSE) enter executives **/
			FSM_STATE_ENTER_FORCED (4, "CLOSE", state4_enter_exec, "tcp_manager_v3_dt [CLOSE enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [CLOSE enter execs]", state4_enter_exec)
				{
				if (op_ici_attr_get (ici_ptr, "conn_id", &conn_id) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl,
							"TCP CLOSE failed - unable to get connection ID from command ICI.");
				                                
				if (op_ici_attr_get (ici_ptr, "local_key", &local_key) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl, "TCP CLOSE failed - unable to get local_key from command ICI.");
				
				/* Find a matching TCP socket process.	*/
				tcb_ptr = tcp_tcb_from_id (tcp_dt_handle, conn_id, local_key);
				if (tcb_ptr != OPC_NIL)
					{
					ev_ptr->event = TCPC_EV_CLOSE;
					if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
								"TCP CLOSE failed - unable to invoke TCP socket process.");
					}
				else
					{
					if (tcp_trace_active)
						{
						sprintf (msg0, "CLOSE command issued to invalid connection (%d)", conn_id);
						op_prg_odb_print_major (msg0, OPC_NIL);
						}
					tcp_invalid_conn_log_write (conn_id, "CLOSE");
				
					if (op_ici_attr_set (ici_ptr, "conn_id", TCPC_CONN_ID_INVALID) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
								"TCP CLOSE was unable to reset connection ID in command ICI for invalid connection.");
					}
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** state (CLOSE) exit executives **/
			FSM_STATE_EXIT_FORCED (4, "CLOSE", "tcp_manager_v3_dt [CLOSE exit execs]")


			/** state (CLOSE) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "CLOSE", "active", "tcp_manager_v3_dt [CLOSE -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (ABORT) enter executives **/
			FSM_STATE_ENTER_FORCED (5, "ABORT", state5_enter_exec, "tcp_manager_v3_dt [ABORT enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [ABORT enter execs]", state5_enter_exec)
				{
				if (op_ici_attr_get (ici_ptr, "conn_id", &conn_id) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl,
							"TCP ABORT failed - unable to get connection ID from command ICI.");
				                                
				if (op_ici_attr_get (ici_ptr, "local_key", &local_key) == OPC_COMPCODE_FAILURE)
				    op_prg_log_entry_write (ll_loghndl, "TCP SEND failed - unable to get local_key from command ICI.");
				                                
				tcb_ptr = tcp_tcb_from_id (tcp_dt_handle, conn_id, local_key);
				
				if (tcb_ptr != OPC_NIL)
					{
					ev_ptr->event = TCPC_EV_ABORT;
					if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
						op_prg_log_entry_write (ll_loghndl,
								"TCP ABORT failed - unable to invoke TCP socket process.");
					}
				else
					{
					if (tcp_trace_active)
						{
						sprintf (msg0, "ABORT command issued to invalid connection (%d)", conn_id);
						op_prg_odb_print_major (msg0, OPC_NIL);
						}
				
					tcp_invalid_conn_log_write (conn_id, "ABORT");
				
					/*	Send an abort indication to the application.			*/
					intf_ici_ptr = op_ici_create ("tcp_status_ind");
					if (intf_ici_ptr == OPC_NIL ||
						op_ici_attr_set (intf_ici_ptr, "conn_id", conn_id) == OPC_COMPCODE_FAILURE ||
						op_ici_attr_set (intf_ici_ptr, "status", TCPC_IND_ABORTED) == OPC_COMPCODE_FAILURE)
						{
						op_prg_odb_print_major ("Unable to create or initialize status indication ICI.",
							"Application will not be notified that this connection has aborted.",
							OPC_NIL);
						}
					else
						{
						op_ici_install (intf_ici_ptr);
						abort_evh = op_intrpt_schedule_remote (op_sim_time (), 0, op_intrpt_source ());
						if (op_ev_valid (abort_evh) == OPC_FALSE)
							{
							op_prg_odb_print_major ("Unable to schedule remote interrupt at application.",
								"Application will not be notified that this connection has aborted.",
								OPC_NIL);
							}
						}
					}
				
				/*	Set number of connections aborted to 1 as statistic capture	*/
				/*	mode "sum" adds all the aborted connections. Update the		*/
				/*	statistics maintained to keep track of the TCP aborts.		*/
				op_stat_write (abort_conn_stathandle, 1.0);
				
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** state (ABORT) exit executives **/
			FSM_STATE_EXIT_FORCED (5, "ABORT", "tcp_manager_v3_dt [ABORT exit execs]")


			/** state (ABORT) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "ABORT", "active", "tcp_manager_v3_dt [ABORT -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (SEG_RCV) enter executives **/
			FSM_STATE_ENTER_FORCED (6, "SEG_RCV", state6_enter_exec, "tcp_manager_v3_dt [SEG_RCV enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [SEG_RCV enter execs]", state6_enter_exec)
				{
				/* Get the received packet. */
				ev_ptr->pk_ptr = op_pk_get (intrpt_strm);
				if (ev_ptr->pk_ptr == OPC_NIL)
						{
						low_level_error = OPC_TRUE;
						op_prg_log_entry_write (ll_loghndl,
								"TCP SEG_RCV failed - unable to get packet from input stream.");
						}
				else
					{
					/* Determine the socket addresses for the packet. */
					if ((op_ici_attr_get (ici_ptr, "src_addr", &addr_ptr) == OPC_COMPCODE_FAILURE) ||
						(op_pk_nfd_access (ev_ptr->pk_ptr, "fields", &pk_fd_ptr) == OPC_COMPCODE_FAILURE))
						{
						low_level_error = OPC_TRUE;
						op_prg_log_entry_write (ll_loghndl,
								"TCP SEG_RCV failed - unable to obtain addressing information from ICI or packet.");
				
						rem_addr = INETC_ADDRESS_INVALID;
						}
					else
						{
						/* Store the address and prot information locally.	*/
						rem_addr = *addr_ptr;
						/* Free the memory allocated to the addr_ptr. (But	*/
						/* not to the embedded address).					*/
						op_prg_mem_free (addr_ptr);
				
						rem_port = pk_fd_ptr->src_port;
						local_port = pk_fd_ptr->dest_port;
				
						/* Determine the local and remote TCP conenction	*/
						/* process "key" identifiers (maintained locally).	*/
						local_key  = pk_fd_ptr->remote_key;
						remote_key = pk_fd_ptr->local_key;
						}
				
					/* Determine the destination address in the packet,	*/
					/* which we will use as the source address.			*/
					if (op_ici_attr_get (ici_ptr, "dest_addr", &addr_ptr) == OPC_COMPCODE_FAILURE)
						{
						low_level_error = OPC_TRUE;
						op_prg_log_entry_write (ll_loghndl,
								"TCP SEG_RCV failed - unable to obtain addressing information from ICI.");
						local_addr = INETC_ADDRESS_INVALID;
						}
					else
						{
						local_addr = *addr_ptr;
						/* Free the memory allocated to the addr_ptr. (But	*/
						/* not to the embedded address).					*/
						op_prg_mem_free (addr_ptr);
						}
				
					/* TCP does not use the interface received information.	*/
					/* Just free the memory allocated to this field.		*/
					if (op_ici_attr_get (ici_ptr, "interface_received", &addr_ptr) != OPC_COMPCODE_FAILURE)
						{
						inet_address_destroy_dynamic (addr_ptr);
						}
					}
				
				if (low_level_error == OPC_FALSE)
					{
					/* Get the control flags from the packet. */
					ev_ptr->flags = pk_fd_ptr->flags;
					
					seg_seq = pk_fd_ptr->seq_num;
					seg_len = pk_fd_ptr->data_len;
					if (ev_ptr->flags & TCPC_FLAG_ACK)
						seg_ack = pk_fd_ptr->ack_num;
				
					/* Collect trace information. */
					if (tcp_trace_active)
						{
						tcp_seg_msg_print ("Receiving <--", seg_seq, seg_ack, seg_len, ev_ptr->flags);
						}
				
					/* Find the destination TCB from the socket information.	*/
					tcb_ptr = tcp_tcb_from_addrs (tcp_dt_handle, tcb_list, ll_loghndl, local_key,
													remote_key, local_port, rem_addr, rem_port);
					if (tcb_ptr == OPC_NIL)
						{
						/* Full socket match was not found; packet may still be valid. */
						if (ev_ptr->flags & TCPC_FLAG_RST)
							{
							/* If the segment is an RST, ignore it. */
							tcp_rst_rcvd_log_write ();
																	 
							if (tcp_trace_active)
								op_prg_odb_print_major ("Unexpected RST received: Destroyed", OPC_NIL);
							op_pk_destroy (ev_ptr->pk_ptr);
							}
				
						else if (ev_ptr->flags & TCPC_FLAG_ACK)
							{
							/* If the segment is an ACK, respond with an RST (no ACK). */
							if (tcp_trace_active)
								op_prg_odb_print_major ("Unexpected ACK received: Responding with RST", OPC_NIL);
				
							tcp_invalid_ack_rcvd_log_write ();
				
							tcp_mgr_rst_send (seg_ack, 0, 0, local_port, rem_addr, rem_port, local_addr, local_key, remote_key);
							op_pk_destroy (ev_ptr->pk_ptr);
							}
				
						else if (ev_ptr->flags & TCPC_FLAG_SYN)
							{
							/* If the segment is a SYN, it may be acceptable	*/
							/* for a connection in state LISTEN.  Look for		*/
							/* possible matches in connections with remote		*/
							/* sockets that are not yet completely specified.	*/
							if ((max_connections == OPC_INT_INFINITY) ||
								(tcp_active_conn_count_reached () == OPC_FALSE))
								{
								tcb_ptr = tcp_tcb_best_match (tcb_list, ll_loghndl, local_port, rem_addr, rem_port);
								if (tcb_ptr != OPC_NIL)
									{
									/* Set the dispatch table key index to be later	*/
									/* used to expedite connection process lookup.	*/
									tcb_ptr->remote_key = remote_key;
				
									/* Initialize diagnostic structure				*/
									if (tcb_ptr->conn_id < CONNECTION_STATISTIC_COUNT)
										{
										if ((! inet_address_valid (diag_ptr[tcb_ptr->conn_id].tcp_rem_addr)) && 
											(!strcmp (tcb_ptr->state_name, "LISTEN")))
											{
											/*	De-allocate the memory allocated to	*/
											/*	the original data structure element	*/
											/*	to contain the remote IP address.	*/
											inet_address_destroy (diag_ptr[tcb_ptr->conn_id].tcp_rem_addr);
					
											/*	Assign new value for the remote		*/
											/*	address and port information.		*/
											diag_ptr[tcb_ptr->conn_id].tcp_rem_addr = inet_address_copy (rem_addr);
											diag_ptr[tcb_ptr->conn_id].tcp_rem_port = rem_port;
											diag_ptr[tcb_ptr->conn_id].start_time = op_sim_time ();
											}
										}
				
									/* Rename the connection based statistics. */
									tcp_connection_based_statistics_register (tcb_ptr, OPC_FALSE);
									
									/* Partial socket match was found. */
									ev_ptr->event = TCPC_EV_SEG_ARRIVAL;
				
									/* 	Server received a SYN message and needs to specify Type of Service (ToS) */
									/*	for all outgoing packets. This value is saved in ip_encap_req ICI that*/
									/*	accompanies each packet sent by tcp to ip. The value specified by the 	 */
									/*	server was read from the higher layer ICI in OPEN state. In a case,	 */
									/*	the server specified the value as "As Requested by Server", its ToS is 	 */
									/*	overwritten by ToS specified by client. 								 */
									if (tcb_ptr->type_of_service == -1)
										{
										op_ici_attr_get (ici_ptr, "Type of Service", &(tcb_ptr->type_of_service));
										op_ici_attr_set (ip_encap_ici_info.ip_encap_req_ici_ptr, "Type of Service",
															tcb_ptr->type_of_service);
										}
				
									/* Write the updated active connection stats.           */
									op_stat_write (active_conn_handle, (double)(1.0));
				
									/* If the local address field was not set earlier,			*/
									/* Fill it now with the tcb with the						*/
									/* destination address of the received segment, which was	*/
									/* stored earlier under the local variable local_addr.		*/
									if (! inet_address_valid (tcb_ptr->local_addr))
										{
										tcb_ptr->local_addr = inet_address_copy (local_addr);
										}
				
									/* Collect trace information. */
									if (tcp_trace_active)
										{
										sprintf (msg0, "Connection ID: %d", tcb_ptr->conn_id);
										op_prg_odb_print_minor (msg0, OPC_NIL);
										}
				
									if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
										op_prg_log_entry_write (ll_loghndl,
											"Connection process was not invoked to handle TCP segment - invocation failed.");
				
									/* If Reset was received for a connection which was in      */
									/* SYN_RCVD state before it moved to LISTEN state, then     */
									/* decrement the number of active connections.              */
									if ((ev_ptr->flags & TCPC_FLAG_RST) &&
										(strcmp (tcb_ptr->state_name, "LISTEN") == 0) &&
										(strcmp (previous_state, "SYN_RCVD") == 0))
										{
										/* Write the updated active connection stats.           */
										op_stat_write (active_conn_handle, (double)(-1.0));
										}
									}
								else
									{
									/* No match was found.  Send an RST ACK. */
									if (tcp_trace_active)
										op_prg_odb_print_major ("Unexpected SYN received: Responding with RST ACK",
											OPC_NIL);
				
									inet_address_print (rem_addr_str, rem_addr);
									tcp_unexpected_syn_log_write (local_port, rem_port, rem_addr_str);
				
									tcp_mgr_rst_send (0, 1, seg_seq + seg_len, local_port, rem_addr, rem_port, local_addr, local_key, remote_key); 
					
									/* Destroy the received packet. */
									op_pk_destroy (ev_ptr->pk_ptr);
									}			
								}
							else
								{
								/* The maximum number of TCP sessions has been exceeded.	*/
								/* Send an RST ACK. 										*/
								
								if (tcp_trace_active)
									{
									op_prg_odb_print_major (
											"TCP process was unable to open a new connection.\n", 
											"The Active Connections Threshold has been exceeded.\n", OPC_NIL);
									}
								
								tcp_mgr_rst_send (0, 1, seg_seq + seg_len, local_port, rem_addr, rem_port, local_addr, local_key, remote_key); 
					
								/* Destroy the received packet. */
								op_pk_destroy (ev_ptr->pk_ptr);
								}
							}
						else
							{
							/* No match was found.  Respond with RST ACK. */
							if (tcp_trace_active)
								op_prg_odb_print_major ("Unexpected segment received: Responding with RST ACK", OPC_NIL);
				
							inet_address_print (rem_addr_str, rem_addr);
							tcp_unexpected_seg_log_write (local_port, rem_port, rem_addr_str);
				
							tcp_mgr_rst_send (0, 1, seg_seq + seg_len, local_port, rem_addr, rem_port, local_addr, local_key, remote_key); 
					
							/* Destroy the received packet. */		
							op_pk_destroy (ev_ptr->pk_ptr);
							}
						} 
					else
						{
						/* Full socket match was found. */
						ev_ptr->event = TCPC_EV_SEG_ARRIVAL;
						
						/* Check what is the status of the ECN-related information.	*/
						/* If the incoming segment experienced congestion in the	*/
						/* network somewhere without getting dropped, then it must	*/
						/* have the CE bit set in the IP datagram that carried this	*/
						/* packet. IP passes this information in the interface ICI.	*/
						op_ici_attr_get (ici_ptr, "congestion_experienced", &(ev_ptr->congestion_experienced));
				
						/* If the local address field was not set earlier,			*/
						/* Fill it now with the tcb with the						*/
						/* destination address of the received segment, which was	*/
						/* stored earlier under the local variable local_addr.		*/
						if (! inet_address_valid (tcb_ptr->local_addr))
							{
							tcb_ptr->local_addr = inet_address_copy (local_addr);
							}
						
						/* Fill the remote address field of the tcb */
						if (! inet_address_valid (tcb_ptr->rem_addr))
							tcb_ptr->rem_addr = inet_address_copy (rem_addr);
				
						/* Set the dispatch table key index to be later	*/
						/* used to expedite connection process lookup.	*/
						tcb_ptr->remote_key = remote_key;
				
						/* Collect trace information. */
						if (tcp_trace_active)
							{
							sprintf (msg0, "Connection ID: %d", tcb_ptr->conn_id);
				            sprintf (msg1, " Local DT Key: %d", tcb_ptr->local_key);
				            sprintf (msg2, "Remote DT key: %d", tcb_ptr->remote_key);
				            op_prg_odb_print_minor (msg0, msg1, msg2, OPC_NIL);                                    
							}
				
						if (op_pro_invoke (tcb_ptr->conn_pro, ev_ptr) == OPC_COMPCODE_FAILURE)
							op_prg_log_entry_write (ll_loghndl,
									"Connection process was not invoked to handle TCP segment - invocation failed.");
						}
					}
				
				/* Destroy the indication ICI. */
				op_ici_destroy (ici_ptr);
				
				/* Free the memory allocated to the IP Address fields in the ICI.	*/
				inet_address_destroy (rem_addr);
				inet_address_destroy (local_addr);
				}
				FSM_PROFILE_SECTION_OUT (state6_enter_exec)

			/** state (SEG_RCV) exit executives **/
			FSM_STATE_EXIT_FORCED (6, "SEG_RCV", "tcp_manager_v3_dt [SEG_RCV exit execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [SEG_RCV exit execs]", state6_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state6_exit_exec)


			/** state (SEG_RCV) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "SEG_RCV", "active", "tcp_manager_v3_dt [SEG_RCV -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (STATUS) enter executives **/
			FSM_STATE_ENTER_FORCED (7, "STATUS", state7_enter_exec, "tcp_manager_v3_dt [STATUS enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [STATUS enter execs]", state7_enter_exec)
				{
				if (op_ici_attr_get (ici_ptr, "conn_id", &conn_id) == OPC_COMPCODE_FAILURE ||
					op_ici_attr_get (ici_ptr, "status", &status) == OPC_COMPCODE_FAILURE)
					op_prg_log_entry_write (ll_loghndl,
							"TCP STATUS failed - unable to get connection ID  or status from indication ICI.");
				else
					{	
					switch (status)
						{
						case TCPC_IND_CLOSED:
						case TCPC_IND_ABORTED:
							{
							if (tcp_trace_active)
								{
								sprintf (msg0, "Removing connection (%d) from TCB list.", conn_id);
								op_prg_odb_print_minor (msg0, OPC_NIL);
								}		
					
							list_size = op_prg_list_size (tcb_list);
							for (i = 0; i < list_size; i++)
								{
								tcb_ptr = (TcpT_Tcb *) op_prg_list_access (tcb_list, i);
								if (tcb_ptr == OPC_NIL)
									op_prg_log_entry_write (ll_loghndl,
											"Unable to get TCB from list; skipping to next TCB.");
								else if (tcb_ptr->conn_id == conn_id)
									{
								    /* Write the updated active connection stats.           */
									op_stat_write (active_conn_handle, (double)(-1.0));
				
									/* Free the associated memory with the transport control*/
									/* block of TCP.										*/
									op_prg_list_remove (tcb_list, i);
									tcp_tcb_free (tcb_ptr);
					
									/* Initialize diagnostic array with end time of the connection */
									if (conn_id < CONNECTION_STATISTIC_COUNT)
										diag_ptr[conn_id].end_time = op_sim_time ();
					
									break;
									}
								}
				
							/* Destroy the associated ICI.	*/
							op_ici_destroy (ici_ptr);
					
							break;
							}
					
						default:
							{
							if (tcp_trace_active)
								{
								op_prg_odb_print_major ("Unknown status indication received from connection",
									OPC_NIL);
								}
				
							tcp_unknown_ind_log_write (conn_id);
				
							break;
							}
						}
					}
				}
				FSM_PROFILE_SECTION_OUT (state7_enter_exec)

			/** state (STATUS) exit executives **/
			FSM_STATE_EXIT_FORCED (7, "STATUS", "tcp_manager_v3_dt [STATUS exit execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [STATUS exit execs]", state7_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state7_exit_exec)


			/** state (STATUS) transition processing **/
			FSM_TRANSIT_FORCE (0, state0_enter_exec, ;, "default", "", "STATUS", "active", "tcp_manager_v3_dt [STATUS -> active : default / ]")
				/*---------------------------------------------------------*/



			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED (8, "init", state8_enter_exec, "tcp_manager_v3_dt [init enter execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [init enter execs]", state8_enter_exec)
				{
				/*	Initialize the state variables and notification log handles. */
				tcp_mgr_sv_init ();
				tcp_notification_log_init ();
				
				/* If not already done, define the tcp_manager_v3 event pooled memory object. */
				if (ev_defined == OPC_FALSE)
					{
					ev_defined = OPC_TRUE;
					ev_pmh = op_prg_pmo_define ("tcp_manager_v3 event", sizeof (TcpT_Event), 16);
					}
				
				/*	Without memory to hold the event, this model will be disabled.	*/
				ev_ptr = (TcpT_Event *) op_prg_pmo_alloc (ev_pmh);
				if (ev_ptr == OPC_NIL)
					{
					op_prg_log_entry_write (ll_loghndl, "Unable to create event structure.");
					op_sim_end ("Please check simulation log for simulation kernel errors.", "", "", "");
					}
				
				/* Create a dispatch table to be used to manage		*/
				/* spawned connections.								*/
				tcp_dt_handle = oms_dt_table_create ("TCP", 32);
				
				/* Register the process in the model-wide registry. */
				own_process_record_handle = (OmsT_Pr_Handle) 
					oms_pr_process_register (own_node_objid, own_mod_objid, own_prohandle, proc_model_name);
				
				/* Register the protocol attribute in the registry. */
				oms_pr_attr_set (own_process_record_handle, 
					"protocol",			OMSC_PR_STRING,		"tcp", 
					"Local Port",		OMSC_PR_POINTER,	local_port_ptr, 
					"Dt Handle",		OMSC_PR_POINTER,	tcp_dt_handle,
					OPC_NIL);
				
				/* Schedule a self interrupt for this process at	*/
				/* the current time to allow lower layer processes	*/
				/* to register in process registry.					*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				/** Register this higher layer protocolwith label,	**/
				/** tcp and id, IpC_Protocol_Tcp.					**/
				
				/* Set the protocol type.							*/
				higher_layer_protocol_type = IpC_Protocol_Tcp;
				
				/* Register this higher layer protocol with	the		*/
				/* given higher layer protocol type.				*/
				Inet_Higher_Layer_Protocol_Register ("tcp", &higher_layer_protocol_type);
				
				/* Schedule a function that will print log messages about possible 	*/
				/* configuration problems encountered by connection processes		*/
				if ((log_call_scheduled == OPC_FALSE) && (op_intrpt_type () != OPC_INTRPT_ENDSIM))
					{
					/* This is the first time the function is called.	*/
					
					op_intrpt_schedule_call (OPC_INTRPT_SCHED_CALL_ENDSIM, 0, 
							tcp_rcv_wnd_low_log_write, OPC_NIL);
						
					log_call_scheduled = OPC_TRUE;
					}
				}
				FSM_PROFILE_SECTION_OUT (state8_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (17,"tcp_manager_v3_dt")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (8, "init", "tcp_manager_v3_dt [init exit execs]")
				FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [init exit execs]", state8_exit_exec)
				{
				/* Determine the interrupt type as the model perform .	*/
				intrpt_type = op_intrpt_type ();
				
				if ((intrpt_type != OPC_INTRPT_FAIL) && (intrpt_type != OPC_INTRPT_RECOVER))
					{
					/* Obtain the process record handle of the lan process,	*/
					/* If this node happens to be a LAN node.				*/
					proc_record_handle_list_ptr = op_prg_list_create ();
					oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_list_ptr, 
						"node objid",		OMSC_PR_OBJID,		own_node_objid,
					"node_type",		OMSC_PR_STRING,		"lan_mac",
					OPC_NIL);
				
					/* There should only be one process registered as LAN.	*/
					record_handle_list_size = op_prg_list_size (proc_record_handle_list_ptr);
					if (record_handle_list_size == 1)
						{
						/*	Obtain total number of workstations in this node.	*/
						/*	This is equal to the server id.						*/
						proc_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
						oms_pr_attr_get (proc_record_handle, "wkstn count", OMSC_PR_NUMBER, &server_id);
						lan_server_identifier = (int) server_id;
				
						/*	Obtain lan handle from llm package.					*/
						my_lanhandle = llm_lan_handle_get (own_node_objid);
						}
					else
						{
						/* Set LAN-object related attributes as undefined values.	*/
						lan_server_identifier = OPC_INT_UNDEF;
						my_lanhandle  = (LlmT_Lan_Handle) OPC_NIL;
						}
				
					/* Deallocate no longer needed process registry information	*/
					while (op_prg_list_size (proc_record_handle_list_ptr))
						op_prg_list_remove (proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
					op_prg_mem_free (proc_record_handle_list_ptr);
					}
				else if (op_intrpt_source () == own_node_objid)
					{
					if (intrpt_type == OPC_INTRPT_FAIL)
						{
						/* The node surrounding this module has failed.	*/
						
						if (tcp_parameter_ptr->node_failed == OPC_FALSE)
							tcp_parameter_ptr->node_failed = OPC_TRUE;
						}
					else 
						{
						/* The node surrounding this module has recovered.	*/
				
						if (tcp_parameter_ptr->node_failed == OPC_TRUE)
							tcp_parameter_ptr->node_failed = OPC_FALSE;
						}
					}
				}
				FSM_PROFILE_SECTION_OUT (state8_exit_exec)


			/** state (init) transition processing **/
			FSM_PROFILE_SECTION_IN ("tcp_manager_v3_dt [init trans conditions]", state8_trans_conds)
			FSM_INIT_COND (FAILURE_RECOVERY)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("init")
			FSM_PROFILE_SECTION_OUT (state8_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 8, state8_enter_exec, ;, "FAILURE_RECOVERY", "", "init", "init", "tcp_manager_v3_dt [init -> init : FAILURE_RECOVERY / ]")
				FSM_CASE_TRANSIT (1, 0, state0_enter_exec, ;, "default", "", "init", "active", "tcp_manager_v3_dt [init -> active : default / ]")
				}
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (8,"tcp_manager_v3_dt")
		}
	}




void
_op_tcp_manager_v3_dt_diag (OP_SIM_CONTEXT_ARG_OPT)
	{

#if defined (OPD_ALLOW_ODB)

#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__;
#endif

	FIN_MT (_op_tcp_manager_v3_dt_diag ())

	if (1)
		{
		/* Temporary Variables */
		int					intrpt_type = OPC_INT_UNDEF;
		int					intrpt_strm = OPC_INT_UNDEF;
		int					intrpt_code = OPC_INT_UNDEF;
		Ici*				ici_ptr = OPC_NIL;
		Ici*				intf_ici_ptr = OPC_NIL;
		Objid				strm_objid = OPC_OBJID_INVALID;
		
		int					higher_layer_protocol_type;
		
		List*				proc_record_handle_list_ptr;
		int					record_handle_list_size;
		OmsT_Pr_Handle		proc_record_handle;
		double				server_id;
		
		TcpT_Conn_Id		conn_id;
		TcpT_Port			local_port;
		OmsT_Dt_Key			local_key = OmsC_Dt_Key_Undefined;
		OmsT_Dt_Key			remote_key = OmsC_Dt_Key_Undefined;
		
		InetT_Address		rem_addr;
		InetT_Address		local_addr;
		InetT_Address*		addr_ptr;
		Boolean				inet_support;
		char				rem_addr_str [IPC_ADDR_STR_LEN];
		char				local_addr_str [IPC_ADDR_STR_LEN];
		int					type_of_service;
		
		TcpT_Port			rem_port;
		int					strm_index;
		int					urgent;
		
		int					list_size;
		int					i;
		
		TcpT_Tcb*			tcb_ptr = OPC_NIL;
		TcpT_Tcb*			test_tcb_ptr;
		int					seg_ack = 0;
		int					seg_seq;
		int					seg_len;
		
		char				msg0 [512], msg1 [512], msg2 [512];
		int					status;
		
		static int			ev_defined = OPC_FALSE;
		static Pmohandle	ev_pmh;
		static int			tcb_defined = OPC_FALSE;
		static Pmohandle	tcb_pmh;
		
		int					ctr;
		char				scratch_str [512];
		char				scratch_str1 [512];
		int					my_node_id, my_subnet_id;
		
		double				pk_size;
		double				byte_load;
		
		Boolean				conn_failed = OPC_FALSE;
		Boolean				low_level_error = OPC_FALSE;
		Evhandle			abort_evh;
		
		TcpT_Seg_Fields*	pk_fd_ptr;
		char                previous_state [16];
		Boolean				invoke_child_process;
		/* End of Temporary Variables */

		/* Diagnostic Block */


		BINIT
		{
		op_prg_odb_print_major ("TCB list:", OPC_NIL);
		
		list_size = op_prg_list_size (tcb_list);
		for (i = 0; i < list_size; i++)
			{
			tcb_ptr = (TcpT_Tcb *) op_prg_list_access (tcb_list, i);
		
			/* Print socket information. */
			sprintf (msg0, "Connection (%d) information: state (%s)",
				tcb_ptr->conn_id, tcb_ptr->state_name);
			sprintf (msg1, "Application objid (%d), Type of Service: %s,",
				tcb_ptr->app_objid, ip_qos_tos_value_to_tos_name_convert ((OmsT_Qm_Tos)tcb_ptr->type_of_service));
			sprintf (msg2, "traffic through stream (%d)", tcb_ptr->strm_index);
			op_prg_odb_print_major (msg0, msg1, msg2, OPC_NIL);
		
			sprintf (msg0, "Local port: (%5d)\tRemote port: (%5d)", tcb_ptr->local_port, tcb_ptr->rem_port);
			sprintf (msg1, " Local Key: (%5d)\t Remote key: (%5d)", tcb_ptr->local_key, tcb_ptr->remote_key);
			inet_address_print (rem_addr_str, tcb_ptr->rem_addr);
			inet_address_print (local_addr_str, tcb_ptr->local_addr);
			sprintf (msg2, "Remote IP Address: (%s)  Advertised Local IP Address: (%s)", rem_addr_str, local_addr_str);
			op_prg_odb_print_minor ("Socket information:", msg0, msg1, OPC_NIL);
			}
		}

		/* End of Diagnostic Block */

		}

	FOUT
#endif /* OPD_ALLOW_ODB */
	}




void
_op_tcp_manager_v3_dt_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{

#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__;
#endif

	FIN_MT (_op_tcp_manager_v3_dt_terminate ())

	if (1)
		{
		/* Temporary Variables */
		int					intrpt_type = OPC_INT_UNDEF;
		int					intrpt_strm = OPC_INT_UNDEF;
		int					intrpt_code = OPC_INT_UNDEF;
		Ici*				ici_ptr = OPC_NIL;
		Ici*				intf_ici_ptr = OPC_NIL;
		Objid				strm_objid = OPC_OBJID_INVALID;
		
		int					higher_layer_protocol_type;
		
		List*				proc_record_handle_list_ptr;
		int					record_handle_list_size;
		OmsT_Pr_Handle		proc_record_handle;
		double				server_id;
		
		TcpT_Conn_Id		conn_id;
		TcpT_Port			local_port;
		OmsT_Dt_Key			local_key = OmsC_Dt_Key_Undefined;
		OmsT_Dt_Key			remote_key = OmsC_Dt_Key_Undefined;
		
		InetT_Address		rem_addr;
		InetT_Address		local_addr;
		InetT_Address*		addr_ptr;
		Boolean				inet_support;
		char				rem_addr_str [IPC_ADDR_STR_LEN];
		char				local_addr_str [IPC_ADDR_STR_LEN];
		int					type_of_service;
		
		TcpT_Port			rem_port;
		int					strm_index;
		int					urgent;
		
		int					list_size;
		int					i;
		
		TcpT_Tcb*			tcb_ptr = OPC_NIL;
		TcpT_Tcb*			test_tcb_ptr;
		int					seg_ack = 0;
		int					seg_seq;
		int					seg_len;
		
		char				msg0 [512], msg1 [512], msg2 [512];
		int					status;
		
		static int			ev_defined = OPC_FALSE;
		static Pmohandle	ev_pmh;
		static int			tcb_defined = OPC_FALSE;
		static Pmohandle	tcb_pmh;
		
		int					ctr;
		char				scratch_str [512];
		char				scratch_str1 [512];
		int					my_node_id, my_subnet_id;
		
		double				pk_size;
		double				byte_load;
		
		Boolean				conn_failed = OPC_FALSE;
		Boolean				low_level_error = OPC_FALSE;
		Evhandle			abort_evh;
		
		TcpT_Seg_Fields*	pk_fd_ptr;
		char                previous_state [16];
		Boolean				invoke_child_process;
		/* End of Temporary Variables */

		/* Termination Block */


		BINIT
		{
		
		}

		/* End of Termination Block */

		}
	Vos_Poolmem_Dealloc_MT (OP_SIM_CONTEXT_THREAD_INDEX_COMMA pr_state_ptr);

	FOUT
	}


/* Undefine shortcuts to state variables to avoid */
/* syntax error in direct access to fields of */
/* local variable prs_ptr in _op_tcp_manager_v3_dt_svar function. */
#undef tcb_list
#undef tcp_parameter_ptr
#undef tcp_ptc_mem
#undef conn_id_new
#undef ev_ptr
#undef diag_ptr
#undef tcp_trace_active
#undef local_port_ptr
#undef own_mod_objid
#undef own_node_objid
#undef own_prohandle
#undef own_process_record_handle
#undef proc_model_name
#undef packet_load_handle
#undef byte_load_handle
#undef packet_sec_load_handle
#undef byte_sec_load_handle
#undef abort_conn_stathandle
#undef ll_loghndl
#undef port_values_wrapped_around
#undef tcp_dt_handle
#undef my_lanhandle
#undef lan_server_identifier
#undef glbl_active_conn_handle
#undef active_conn_handle
#undef print_conn_info
#undef max_connections
#undef num_sess_reach_log_written
#undef log_msg_hash_table
#undef blocked_conn_count_stathandle

#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_tcp_manager_v3_dt_init (int * init_block_ptr)
	{

#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_tcp_manager_v3_dt_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (tcp_manager_v3_dt)",
		sizeof (tcp_manager_v3_dt_state));
	*init_block_ptr = 16;

	FRET (obtype)
	}

VosT_Address
_op_tcp_manager_v3_dt_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype obtype, int init_block)
	{

#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	tcp_manager_v3_dt_state * ptr;
	FIN_MT (_op_tcp_manager_v3_dt_alloc (obtype))

	ptr = (tcp_manager_v3_dt_state *)Vos_Alloc_Object_MT (VOS_THREAD_INDEX_COMMA obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "tcp_manager_v3_dt [init enter execs]";
#endif
		}
	FRET ((VosT_Address)ptr)
	}



void
_op_tcp_manager_v3_dt_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	tcp_manager_v3_dt_state		*prs_ptr;

	FIN_MT (_op_tcp_manager_v3_dt_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (tcp_manager_v3_dt_state *)gen_ptr;

	if (strcmp ("tcb_list" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcb_list);
		FOUT
		}
	if (strcmp ("tcp_parameter_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcp_parameter_ptr);
		FOUT
		}
	if (strcmp ("tcp_ptc_mem" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcp_ptc_mem);
		FOUT
		}
	if (strcmp ("conn_id_new" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->conn_id_new);
		FOUT
		}
	if (strcmp ("ev_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ev_ptr);
		FOUT
		}
	if (strcmp ("diag_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->diag_ptr);
		FOUT
		}
	if (strcmp ("tcp_trace_active" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcp_trace_active);
		FOUT
		}
	if (strcmp ("local_port_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_port_ptr);
		FOUT
		}
	if (strcmp ("own_mod_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_mod_objid);
		FOUT
		}
	if (strcmp ("own_node_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_node_objid);
		FOUT
		}
	if (strcmp ("own_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_prohandle);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("proc_model_name" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->proc_model_name);
		FOUT
		}
	if (strcmp ("packet_load_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->packet_load_handle);
		FOUT
		}
	if (strcmp ("byte_load_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->byte_load_handle);
		FOUT
		}
	if (strcmp ("packet_sec_load_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->packet_sec_load_handle);
		FOUT
		}
	if (strcmp ("byte_sec_load_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->byte_sec_load_handle);
		FOUT
		}
	if (strcmp ("abort_conn_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->abort_conn_stathandle);
		FOUT
		}
	if (strcmp ("ll_loghndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ll_loghndl);
		FOUT
		}
	if (strcmp ("port_values_wrapped_around" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->port_values_wrapped_around);
		FOUT
		}
	if (strcmp ("tcp_dt_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tcp_dt_handle);
		FOUT
		}
	if (strcmp ("my_lanhandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_lanhandle);
		FOUT
		}
	if (strcmp ("lan_server_identifier" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lan_server_identifier);
		FOUT
		}
	if (strcmp ("glbl_active_conn_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->glbl_active_conn_handle);
		FOUT
		}
	if (strcmp ("active_conn_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->active_conn_handle);
		FOUT
		}
	if (strcmp ("print_conn_info" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->print_conn_info);
		FOUT
		}
	if (strcmp ("max_connections" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->max_connections);
		FOUT
		}
	if (strcmp ("num_sess_reach_log_written" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->num_sess_reach_log_written);
		FOUT
		}
	if (strcmp ("log_msg_hash_table" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->log_msg_hash_table);
		FOUT
		}
	if (strcmp ("blocked_conn_count_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->blocked_conn_count_stathandle);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

