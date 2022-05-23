<?php

declare(strict_types=1);

namespace bariscodefx\SSMirai;

use bariscodefx\SSMirai\sockets\TCPSniffer;
use bariscodefx\SSMirai\sockets\UDPSniffer;

class Loop {

	public TCPSniffer $tcp;
	public UDPSniffer $udp;
	public $IPs = [];

	public function __construct() {
		$this->tcp = new TCPSniffer();
		$this->udp = new UDPSniffer();
	}

	public function startSniffing() {
		while(true){
			socket_recv( $this->tcp->socket, $tcp_packet, 65536, 0 );
			socket_recv( $this->udp->socket, $udp_packet, 65536, 0 );

			$this->process($tcp_packet, $this->tcp->socket);
			$this->process($udp_packet, $this->udp->socket);
		}
	}

	public function process($packet, $sock){
		socket_getpeername($sock, $ip, $port);
		if(!in_array($ip, $this->IPs))
		{
			print_r($IPs);
		}
	}

}