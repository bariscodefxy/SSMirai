<?php

declare(strict_types=1);

namespace bariscodefx\SSMirai;

class SSMirai {

	private Loop $loop;

	public function __construct(){
		echo "SSMirai started...";
		$this->loop = new Loop();
	}

}