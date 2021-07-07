<?php  $config = array (
  'baseurlpath' => '/',
  'usenewui' => true,
  'certdir' => 'cert/',
  'loggingdir' => 'log/',
  'datadir' => 'data/',
  'tempdir' => '/tmp/simplesaml',
  'technicalcontact_name' => 'leititia T',
  'technicalcontact_email' => 'leititia.tchimowandji@viveris.fr',
  'timezone' => 'UTC',
  'secretsalt' => 'defaultsecretsalt',
  'auth.adminpassword' => '{SHA512}1ARVn2Auq2/WAqx2gNrL+q3RNjAzXpUfCXrzkA6d4Xa22yhRLy4AC50E+6UTPoscbo31nbOoq51gvkuXzJ6B2w==',
  'admin.protectindexpage' => true,
  'admin.protectmetadata' => false,
  'admin.checkforupdates' => true,
  'trusted.url.domains' => 
  array (
  ),
  'trusted.url.regex' => false,
  'enable.http_post' => false,
  'assertion.allowed_clock_skew' => 180,
  'debug' => 
  array (
    'saml' => false,
    'backtraces' => true,
    'validatexml' => false,
  ),
  'showerrors' => false,
  'errorreporting' => true,
  'logging.level' => 5,
  'logging.handler' => 'file',
  'loggingdir' => 'log/',
  'logging.facility' => 8,
  'logging.processname' => 'simplesamlphp',
  'logging.logfile' => 'simplesamlphp.log',
  'statistics.out' => 
  array (
  ),
  'proxy' => NULL,
  'database.dsn' => 'mysql:host=localhost;dbname=saml',
  'database.username' => 'simplesamlphp',
  'database.password' => 'secret',
  'database.options' => 
  array (
  ),
  'database.prefix' => '',
  'database.driver_options' => 
  array (
  ),
  'database.persistent' => false,
  'database.slaves' => 
  array (
  ),
  'enable.saml20-idp' => true,
  'enable.shib13-idp' => false,
  'enable.adfs-idp' => false,
  'shib13.signresponse' => true,
  'module.enable' => 
  array (
    'exampleauth' => false,
    'core' => true,
    'saml' => true,
    'openidprovider'=> true,
    'idpinstaller'=> true,
    'oidc' => false,
    'openid' => true,
    'authinwebo' => true,
    
  ),
  'session.duration' => 28800,
  'session.datastore.timeout' => 14400,
  'session.state.timeout' => 3600,
  'session.cookie.path' => '/',
  'session.phpsession.savepath' => NULL,
  'session.phpsession.httponly' => true,
  'session.rememberme.enable' => false,
  'session.rememberme.checked' => false,
  'session.rememberme.lifetime' => 1209600,
  'memcache_store.servers' => 
  array (
    0 => 
    array (
      0 => 
      array (
        'hostname' => 'localhost',
      ),
    ),
  ),
  'memcache_store.prefix' => '',
  'memcache_store.expires' => 129600,
  'language' => 
  array (
    'priorities' => 
    array (
      'no' => 
      array (
        0 => 'nb',
        1 => 'nn',
        2 => 'en',
        3 => 'se',
      ),
      'nb' => 
      array (
        0 => 'no',
        1 => 'nn',
        2 => 'en',
        3 => 'se',
      ),
      'nn' => 
      array (
        0 => 'no',
        1 => 'nb',
        2 => 'en',
        3 => 'se',
      ),
      'se' => 
      array (
        0 => 'nb',
        1 => 'no',
        2 => 'nn',
        3 => 'en',
      ),
      'nr' => 
      array (
        0 => 'zu',
        1 => 'en',
      ),
      'nd' => 
      array (
        0 => 'zu',
        1 => 'en',
      ),
      'tw' => 
      array (
        0 => 'st',
        1 => 'en',
      ),
      'nso' => 
      array (
        0 => 'st',
        1 => 'en',
      ),
    ),
  ),
  'language.available' => 
  array (
    0 => 'es',
  ),
  'language.rtl' => 
  array (
    0 => 'ar',
    1 => 'dv',
    2 => 'fa',
    3 => 'ur',
    4 => 'he',
  ),
  'language.default' => 'es',
  'language.parameter.name' => 'language',
  'attributes.extradictionary' => NULL,
  'theme.use' => 'default',
  'template.auto_reload' => false,
  'production' => true,
  'assets' => 
  array (
    'caching' => 
    array (
      'max_age' => 86400,
      'etag' => false,
    ),
  ),
  'idpdisco.enableremember' => true,
  'idpdisco.rememberchecked' => true,
  'idpdisco.validate' => true,
  'idpdisco.extDiscoveryStorage' => NULL,
  'idpdisco.layout' => 'dropdown',
  'authproc.idp' => 
  array (
    30 => 'core:LanguageAdaptor',
    45 => 
    array (
      'class' => 'core:StatisticsWithAttribute',
      'attributename' => 'realm',
      'type' => 'saml20-idp-SSO',
    ),
    50 => 'core:AttributeLimit',
    99 => 'core:LanguageAdaptor',
  ),
  'authproc.sp' => 
  array (
    90 => 'core:LanguageAdaptor',
  ),
  'metadatadir' => 'metadata',
  'metadata.sources' => 
  array (
    0 => 
    array (
      'type' => 'flatfile',
    ),
  ),
  'metadata.sign.enable' => true,
  'metadata.sign.privatekey' => 'simplesaml.key.pem',
  'metadata.sign.privatekey_pass' => NULL,
  'metadata.sign.certificate' => 'simplesaml.crt.pem',
  'store.type' => 'phpsession',
  'store.sql.dsn' => 'sqlite:/path/to/sqlitedatabase.sq3',
  'store.sql.username' => NULL,
  'store.sql.password' => NULL,
  'store.sql.prefix' => 'SimpleSAMLphp',
  'store.redis.host' => 'localhost',
  'store.redis.port' => 6379,
  'store.redis.prefix' => 'SimpleSAMLphp',
  'auth' => 'default-sp',
  'username_attribute' => 'uid',
  'filestore' => '/var/lib/simplesamlphp-openid-provider',
  'enable.wsfed-sp' => false,
  'session.cookie.secure' => false,
); ?>