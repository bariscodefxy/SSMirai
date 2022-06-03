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
			$tcp_buffer = "TCP BUFFER";
			$udp_buffer = "UDP BUFFER";
			@socket_recv( $this->tcp->socket, $tcp_packet, 65536, 0 );
			@socket_recv( $this->udp->socket, $udp_packet, 65536, 0 );

			$this->process($tcp_packet, $this->tcp);
			$this->process($udp_packet, $this->udp);
		}
	}

	public function getTCPSniffer(): TCPSniffer {
		return $this->tcp;
	}

	public function getUDPSniffer(): UDPSniffer {
		return $this->udp;
	}

	public function process($packet, $sniffer){
		if(!$packet || !$sniffer) return;
		if($sniffer instanceof TCPSniffer)
		{
			$ip_header_fmt = 'Cip_ver_len/'
			.'Ctos/'
			.'ntot_len/'
			.'nidentification/'
			.'nfrag_off/'
			.'Cttl/'
			.'Cprotocol/nheader_checksum/Nsource_add/Ndest_add/';
			$ip_header = unpack($ip_header_fmt , $packet);
			if($ip_header['protocol'] == '6')
	  		{
	  			$sniffer->print_tcp_packet($packet);
	  		}
	  		echo "TCP packet \n";
		}else if($sniffer instanceof UDPSniffer) {
			echo "UDP packet \n";
		}
	}

}