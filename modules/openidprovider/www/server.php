<?php

\SimpleSAML\Logger::info('OpenID - Provider: Accessing OpenID Provider endpoint');

// $server = \SimpleSAML\Module\openidprovider\ProviderServer::getInstance();
$server = \SimpleSAML\Module\openidprovider\Auth\Source\Auth\OpenID\ProviderServer::getInstance();
$server->receiveRequest();
