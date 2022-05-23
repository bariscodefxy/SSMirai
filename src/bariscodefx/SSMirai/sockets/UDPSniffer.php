<?php

declare(strict_types=1);

namespace bariscodefx\SSMirai\sockets;

class UDPSniffer {

	public $socket;

	public function __construct() {
		$this->socket = socket_create(AF_INET, SOCK_RAW, SOL_UDP);
		if(!$this->socket) {
			echo "UDP Socket creating failed.";
		}
	}

}