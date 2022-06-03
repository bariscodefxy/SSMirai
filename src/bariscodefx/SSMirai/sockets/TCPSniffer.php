<?php

declare(strict_types=1);

namespace bariscodefx\SSMirai\sockets;

class TCPSniffer {

	public $socket;

	public function __construct() {
		$this->socket = socket_create(AF_INET, SOCK_RAW, SOL_TCP);
		if(!$this->socket) {
			echo "TCP Socket creating failed.";
		}
	}

	public function print_tcp_packet($packet)
	{
		$ip_header_fmt = 'Cip_ver_len/'
		.'Ctos/'
		.'ntot_len/';
		
		$p = unpack($ip_header_fmt , $packet);
		$ip_len = ($p['ip_ver_len'] & 0x0F);
		
		if($ip_len == 5)
		{
			
			//IP Header format for unpack
			$ip_header_fmt = 'Cip_ver_len/'
			.'Ctos/'
			.'ntot_len/'
			.'nidentification/'
			.'nfrag_off/'
			.'Cttl/'
			.'Cprotocol/'
			.'nip_checksum/'
			.'Nsource_add/'
			.'Ndest_add/';
	  	}
	  	else if ($ip_len == 6)
	  	{
	  		//IP Header format for unpack
			$ip_header_fmt = 'Cip_ver_len/'
			.'Ctos/'
			.'ntot_len/'
			.'nidentification/'
			.'nfrag_off/'
			.'Cttl/'
			.'Cprotocol/'
			.'nip_checksum/'
			.'Nsource_add/'
			.'Ndest_add/'
			.'Noptions_padding/';
	  	}
	  	
	  	$tcp_header_fmt = 'nsource_port/'
		.'ndest_port/'
		.'Nsequence_number/'
		.'Nacknowledgement_number/'
		.'Coffset_reserved/';
	  	
	  	//total packet unpack format
	  	$total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';
	  	
	  	$p = unpack($total_packet , $packet);
		$tcp_header_len = ($p['offset_reserved'] >> 4);
		
		if($tcp_header_len == 5)
		{
			//TCP Header Format for unpack
			$tcp_header_fmt = 'nsource_port/'
			.'ndest_port/'
			.'Nsequence_number/'
			.'Nacknowledgement_number/'
			.'Coffset_reserved/'
			.'Ctcp_flags/'
			.'nwindow_size/'
			.'nchecksum/'
			.'nurgent_pointer/';
		}
	  	else if($tcp_header_len == 6)
	  	{
			//TCP Header Format for unpack
			$tcp_header_fmt = 'nsource_port/'
			.'ndest_port/'
			.'Nsequence_number/'
			.'Nacknowledgement_number/'
			.'Coffset_reserved/'
			.'Ctcp_flags/'
			.'nwindow_size/'
			.'nchecksum/'
			.'nurgent_pointer/'
			.'Ntcp_options_padding/';
	  	}
	  	
	  	//total packet unpack format
	  	$total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';
		
		//unpack the packet finally
	  	$packet = unpack($total_packet , $packet);
	  	
	  	//prepare the unpacked data
		$sniff = array(
			
			'ip_header' => array(
				'ip_ver' => ($packet['ip_ver_len'] >> 4) ,
				'ip_len' => ($packet['ip_ver_len'] & 0x0F) ,
				'tos' => $packet['tos'] ,
				'tot_len' => $packet['tot_len'] ,
				'identification' => $packet['identification'] ,
				'frag_off' => $packet['frag_off'] ,
				'ttl' => $packet['ttl'] ,
				'protocol' => $packet['protocol'] ,
				'checksum' => $packet['ip_checksum'] ,
				'source_add' => long2ip($packet['source_add']) ,
				'dest_add' => long2ip($packet['dest_add']) ,
			) ,
	  
			'tcp_header' => array(
				'source_port' => $packet['source_port'] ,
				'dest_port' => $packet['dest_port'] ,
				'sequence_number' => $packet['sequence_number'] ,
				'acknowledgement_number' => $packet['acknowledgement_number'] ,
				'tcp_header_length' => ($packet['offset_reserved'] >> 4) ,
				
				'tcp_flags' => array(
					'cwr' => (($packet['tcp_flags'] & 0x80) >> 7) ,
					'ecn' => (($packet['tcp_flags'] & 0x40) >> 6) ,
					'urgent' => (($packet['tcp_flags'] & 0x20) >> 5 ) ,
					'ack' => (($packet['tcp_flags'] & 0x10) >>4) ,
					'push' => (($packet['tcp_flags'] & 0x08)>>3) ,
					'reset' => (($packet['tcp_flags'] & 0x04)>>2) ,
					'syn' => (($packet['tcp_flags'] & 0x02)>>1) ,
					'fin' => (($packet['tcp_flags'] & 0x01)) ,
				) ,
				
				'window_size' => $packet['window_size'] ,
				'checksum' => $packet['checksum'] . ' [0x'.dechex($packet['checksum']).']',
			) ,
	  
	  		'data' => hex_to_str($packet['data'])
		);

		//print the unpacked data
		print_r($sniff);
	}

}