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

}