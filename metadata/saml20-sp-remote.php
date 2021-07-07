<?php

/**
 * SAML 2.0 remote SP metadata for SimpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */

/*
 * Example SimpleSAMLphp SAML 2.0 SP
 */
$metadata['https://saml2sp.example.org'] = [
    'AssertionConsumerService' => 'https://saml2sp.example.org/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
    'SingleLogoutService' => 'https://saml2sp.example.org/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
];

/*
 * This example shows an example config that works with Google Workspace (G Suite / Google Apps) for education.
 * What is important is that you have an attribute in your IdP that maps to the local part of the email address at
 * Google Workspace. In example, if your Google account is foo.com, and you have a user that has an email john@foo.com, then you
 * must set the simplesaml.nameidattribute to be the name of an attribute that for this user has the value of 'john'.
 */
$metadata['google.com'] = [
    'AssertionConsumerService' => 'https://www.google.com/a/g.feide.no/acs',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'uid',
    'simplesaml.attributes' => false,
];

$metadata['https://legacy.example.edu'] = [
    'AssertionConsumerService' => 'https://legacy.example.edu/saml/acs',
    /*
     * Currently, SimpleSAMLphp defaults to the SHA-256 hashing algorithm.
     * Uncomment the following option to use SHA-1 for signatures directed
     * at this specific service provider if it does not support SHA-256 yet.
     *
     * WARNING: SHA-1 is disallowed starting January the 1st, 2014.
     * Please refer to the following document for more information:
     * http://csrc.nist.gov/publications/nistpubs/800-131A/sp800-131A.pdf
     */
    //'signature.algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
];
$metadata['https://sir2.rediris.es/hub/metadata/sml/saml2/'] = array (
  'entityid' => 'https://sir2.rediris.es/hub/metadata/sml/saml2/',
  'contacts' => 
  array (
  ),
  'metadata-set' => 'saml20-sp-remote',
  'AssertionConsumerService' => 
  array (
    0 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'https://sir2.rediris.es/hub/SAML2/sml_sp_acs.php',
      'index' => 0,
    ),
  ),
  'SingleLogoutService' => 
  array (
  ),
  'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'keys' => 
  array (
    0 => 
    array (
      'encryption' => false,
      'signing' => true,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIIE4jCCA8qgAwIBAgIJANcJwbBM6rtYMA0GCSqGSIb3DQEBCwUAMIGmMQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxEDAOBgNVBAoTB1JlZElSSVMxKTAnBgNVBAsTIFNlcnZpY2lvIGRlIElkZW50aWRhZCBkZSBSZWRJUklTMRgwFgYDVQQDEw9zaXIyLnJlZGlyaXMuZXMxHjAcBgkqhkiG9w0BCQEWD3NpcjJAcmVkaXJpcy5lczAeFw0xNTEyMTcxMTQ3MjdaFw0zODA5MDIxMTQ3MjdaMIGmMQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxEDAOBgNVBAoTB1JlZElSSVMxKTAnBgNVBAsTIFNlcnZpY2lvIGRlIElkZW50aWRhZCBkZSBSZWRJUklTMRgwFgYDVQQDEw9zaXIyLnJlZGlyaXMuZXMxHjAcBgkqhkiG9w0BCQEWD3NpcjJAcmVkaXJpcy5lczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmRmlKEMw0eDJO4xaq5hZgj/MH/g/5DE+1EzDWidwYmwaPGu/DipnzxQjBzp9iHg+hZGBQQXp4HD7AXebtNoG/6BYzjk7TQyBbetNRhmWz8jgc7alq8z5nKgmoJk+j8MqBDPrIfV6r5V1U4khubWXrmDDBfi3vo+dfIKM3yUoHjfM82FnukcLUZ92QOn8QA0+irOrCyGPakVt94sapG9tBGo6fe/ez54jMIJvXXkoknCi9lCGlv/rIwPSjAtQgzoDsO6Hiy+WDETahycRBtdfb9LrnrbRMhpl+IKSd5HaYRhXFSy2RZ5kuemOv4x88x8iDpdzoZck6a+2ie45cU18sCAwEAAaOCAQ8wggELMB0GA1UdDgQWBBS9KXNEqfYlqvWdfPcSVWeB5fboATCB2wYDVR0jBIHTMIHQgBS9KXNEqfYlqvWdfPcSVWeB5fboAaGBrKSBqTCBpjELMAkGA1UEBhMCRVMxDzANBgNVBAgTBk1hZHJpZDEPMA0GA1UEBxMGTWFkcmlkMRAwDgYDVQQKEwdSZWRJUklTMSkwJwYDVQQLEyBTZXJ2aWNpbyBkZSBJZGVudGlkYWQgZGUgUmVkSVJJUzEYMBYGA1UEAxMPc2lyMi5yZWRpcmlzLmVzMR4wHAYJKoZIhvcNAQkBFg9zaXIyQHJlZGlyaXMuZXOCCQDXCcGwTOq7WDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQANPUiLKU5JMhsUUzuP+cNB4KndiLSz/TUnBAroNu7nOGo1CuUKMyJpd2OOC1gVJKqsI3aFZ62uN9u8s9ovTDmcC+qpHg62EjgJnqxWKci6v0eA1WlJ2Noa/wAzx6vXBz1fOlIluR6H9myzwj0oP74sALmjUzhmL5DxVQ5zJ2FZzMi5V04Ru5z0wAcG1EfOhbWIfZdagUVWKqk7M0PyBZynIex/DpgvM+HEbYlLkAh+w83vd6D6gcdpBwXW1EvmUXj5tvAMq39OPwRCe8uEfZmR9oe1z6zzsnQAgPHhy/JEEj8bGyyWuXTkV2asPQIt+2Q+DTQNNohVABiEP6lcnIWq',
    ),
    1 => 
    array (
      'encryption' => true,
      'signing' => false,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIIE4jCCA8qgAwIBAgIJANcJwbBM6rtYMA0GCSqGSIb3DQEBCwUAMIGmMQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxEDAOBgNVBAoTB1JlZElSSVMxKTAnBgNVBAsTIFNlcnZpY2lvIGRlIElkZW50aWRhZCBkZSBSZWRJUklTMRgwFgYDVQQDEw9zaXIyLnJlZGlyaXMuZXMxHjAcBgkqhkiG9w0BCQEWD3NpcjJAcmVkaXJpcy5lczAeFw0xNTEyMTcxMTQ3MjdaFw0zODA5MDIxMTQ3MjdaMIGmMQswCQYDVQQGEwJFUzEPMA0GA1UECBMGTWFkcmlkMQ8wDQYDVQQHEwZNYWRyaWQxEDAOBgNVBAoTB1JlZElSSVMxKTAnBgNVBAsTIFNlcnZpY2lvIGRlIElkZW50aWRhZCBkZSBSZWRJUklTMRgwFgYDVQQDEw9zaXIyLnJlZGlyaXMuZXMxHjAcBgkqhkiG9w0BCQEWD3NpcjJAcmVkaXJpcy5lczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmRmlKEMw0eDJO4xaq5hZgj/MH/g/5DE+1EzDWidwYmwaPGu/DipnzxQjBzp9iHg+hZGBQQXp4HD7AXebtNoG/6BYzjk7TQyBbetNRhmWz8jgc7alq8z5nKgmoJk+j8MqBDPrIfV6r5V1U4khubWXrmDDBfi3vo+dfIKM3yUoHjfM82FnukcLUZ92QOn8QA0+irOrCyGPakVt94sapG9tBGo6fe/ez54jMIJvXXkoknCi9lCGlv/rIwPSjAtQgzoDsO6Hiy+WDETahycRBtdfb9LrnrbRMhpl+IKSd5HaYRhXFSy2RZ5kuemOv4x88x8iDpdzoZck6a+2ie45cU18sCAwEAAaOCAQ8wggELMB0GA1UdDgQWBBS9KXNEqfYlqvWdfPcSVWeB5fboATCB2wYDVR0jBIHTMIHQgBS9KXNEqfYlqvWdfPcSVWeB5fboAaGBrKSBqTCBpjELMAkGA1UEBhMCRVMxDzANBgNVBAgTBk1hZHJpZDEPMA0GA1UEBxMGTWFkcmlkMRAwDgYDVQQKEwdSZWRJUklTMSkwJwYDVQQLEyBTZXJ2aWNpbyBkZSBJZGVudGlkYWQgZGUgUmVkSVJJUzEYMBYGA1UEAxMPc2lyMi5yZWRpcmlzLmVzMR4wHAYJKoZIhvcNAQkBFg9zaXIyQHJlZGlyaXMuZXOCCQDXCcGwTOq7WDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQANPUiLKU5JMhsUUzuP+cNB4KndiLSz/TUnBAroNu7nOGo1CuUKMyJpd2OOC1gVJKqsI3aFZ62uN9u8s9ovTDmcC+qpHg62EjgJnqxWKci6v0eA1WlJ2Noa/wAzx6vXBz1fOlIluR6H9myzwj0oP74sALmjUzhmL5DxVQ5zJ2FZzMi5V04Ru5z0wAcG1EfOhbWIfZdagUVWKqk7M0PyBZynIex/DpgvM+HEbYlLkAh+w83vd6D6gcdpBwXW1EvmUXj5tvAMq39OPwRCe8uEfZmR9oe1z6zzsnQAgPHhy/JEEj8bGyyWuXTkV2asPQIt+2Q+DTQNNohVABiEP6lcnIWq',
    ),
  ),
);
