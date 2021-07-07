<?php  $config = array (
  'admin' => 
  array (
    0 => 'core:AdminPassword',
  ),
  'default-sp' => 
  array (
    0 => 'saml:SP',
    'entityID' => NULL,
    'idp' => NULL,
    'discoURL' => NULL,
  ),
  'openidConsumer' => 
  array (
    0 => 'openid:OpenIDConsumer',
  ),
  'openidprovider' => 
  array(
    0=>'openidprovider:ProviderServer'
),   
  // Config lorsque mon instance est un IdP
  // In-Webo authentication source.
  'inwebo' => array(
    'authinwebo:InWebo',
  ),
  'yahoo' => 
  array (
    0 => 'openid:OpenIDConsumer',
    'target' => 'https://me.yahoo.com/',
    'attributes.ax_required' => 
    array (
      0 => 'http://axschema.org/contact/email',
    ),
    'extension.args' => 
    array (
    ),
  ),
  'example-userpass' => 
  array (
    0 => 'exampleauth:UserPass',
    'u10355:39bkz*5FK' => 
    array (
      'uid' => 
      array (
        0 => 'staff',
      ),
      'commonName' => 'u10355',
      'displayName' => 'u10355',
      'eduPersonAffiliation' => 
      array (
        0 => 'member',
        1 => 'staff',
      ),
      'eduPersonPrincipalName' => 'u10355@inwebo.com',
      'eduPersonScopedAffiliation' => 'staff@inwebo.com',
      'eduPersonTargetedID' => '5eeffb7e0842492da0bccccc1137b2d55233ca34f53c65aa93ee3e7cd0d3173a',
      'mail' => 'u10355@inwebo.com',
      'schacHomeOrganization' => 'inwebo.com',
      'schacHomeOrganizationType' => 'university',
      'schacPersonalUniqueCode' => 'u10355SHA132c27a282f81c47a7ea6b48cce4f01eba2b59acd',
    ),
    'u68999:n#7*SwYPg' => 
    array (
      'uid' => 
      array (
        0 => 'faculty',
      ),
      'commonName' => 'u68999',
      'displayName' => 'u68999',
      'eduPersonAffiliation' => 
      array (
        0 => 'member',
        1 => 'faculty',
      ),
      'eduPersonPrincipalName' => 'u68999@inwebo.com',
      'eduPersonScopedAffiliation' => 'faculty@inwebo.com',
      'eduPersonTargetedID' => '7fc7fe42caa1a8ced084f478b0433eed01c19719b6ad9f6167f2a360663d3509',
      'mail' => 'u68999@inwebo.com',
      'schacHomeOrganization' => 'inwebo.com',
      'schacHomeOrganizationType' => 'university',
      'schacPersonalUniqueCode' => 'u68999SHA1bcdb0ecb1978450d46d2b856426de2a68e22dc6d',
    ),
  ),
); ?>