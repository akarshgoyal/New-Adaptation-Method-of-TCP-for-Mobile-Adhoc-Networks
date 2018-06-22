1. Launch OPNET 11.0.

2. Change the "mod_dirs" preference to include the name of the folder containing the project files.

3. Open the project "tcp_geo_sat.prj". The project includes various scenarios to evaluate and compare the performance of TCP-ADaLR SACK, TCP-ADaLR NewReno, TCP SACK, and TCP NewReno:
	
Scenarios:

(A) Absence of losses due to congestion or satellite link errors
	
(B) Presence of losses due to congestion only: The satellite gateway IP attributes are set as follows:
	Datagram switching rate = 500,000
	Datagram forwarding rate = 360,000
	Forwarding Rate Units = bits/second
	Memory size (bytes) = 37,500.
	
(C) Fairness and friendliness

Other scenarios that may be simulated are:
	
(D) Presence of losses due to satellite link errors only: The BER attribute of the forward and reverse links between the gateway and the receiver is set to various values between 10-5 and 10-9. The ecc-threshold attribute of the transmission receiver of the receiver node model is set to 1.2 x 10-6.

(E) Presence of losses due to both congestion and satellite link errors: The satellite gateway IP attributes are set as described in (B). The BER attribute of the forward and reverse links between the gateway and the receiver is set as described in (D). The ecc-threshold attribute of the transmission receiver of the receiver node model is set as described in (D).

4. Each scenario has two sets of simulation runs (with delayed ACK termed "dack" and without delayed ACK termed "nodack") for an FTP application (downloading file of 50 MB). 


Note:   (a) Satellite gateway IP attributes may vary.
	(b) BER values may vary.
	(c) FTP file sizes may vary.
	(d) HTTP application has been defined in the application configuration menu and may also be simulated.