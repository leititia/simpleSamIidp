<?php

/**
 * IdP custom implementation for InWebo SAML 2.0 authentication.
 *
 * (c) inWebo 2013-2014
 * 
 * Compatible with SimpleSAML 1.9
 * 
 */
class sspmod_authinwebo_IdP_InWebo {


    /**
     * Version modifiée de la fonction receiveAuthnRequest de la classe simpleSAML sspmod_saml_IdP_SAML2
     * Appelée depuis le contrôleur Symfony du favori SAML, action xxxEntryPoint
     * 
     * Receive an authentication request.
     *
     * @param SimpleSAML_IdP $idp  The IdP we are receiving it for.
     * @param SimpleSAML_Configuration $spMetadata The SP metadata loaded from the In-Webo SAML Generic connector in the Symfony Controller
     */
     public static function receiveAuthnRequest(SimpleSAML_IdP $idp, SimpleSAML_Configuration $spMetadata) {

        $idpMetadata = $idp->getConfig();

        $supportedBindings = array(SAML2_Const::BINDING_HTTP_POST);
        if ($idpMetadata->getBoolean('saml20.sendartifact', FALSE)) {
            $supportedBindings[] = SAML2_Const::BINDING_HTTP_ARTIFACT;
        }

        if (isset($_REQUEST['spentityid'])) {
            /* IdP initiated authentication. */

            if (isset($_REQUEST['cookieTime'])) {
                $cookieTime = (int)$_REQUEST['cookieTime'];
                if ($cookieTime + 5 > time()) {
                    /* Less than five seconds has passed since we were here the last time. Cookies are probably disabled */
                    SimpleSAML_Utilities::checkCookie(SimpleSAML_Utilities::selfURL());
                }
            }

            $spEntityId = (string)$_REQUEST['spentityid'];

            if (isset($_REQUEST['RelayState'])) {
                $relayState = (string)$_REQUEST['RelayState'];
            } else {
                $relayState = NULL;
            }

            if (isset($_REQUEST['binding'])){
                $protocolBinding = (string)$_REQUEST['binding'];
            } else {
                $protocolBinding = NULL;
            }

            if (isset($_REQUEST['NameIDFormat'])) {
                $nameIDFormat = (string)$_REQUEST['NameIDFormat'];
            } else {
                $nameIDFormat = NULL;
            }

            $requestId = NULL;
            $IDPList = array();
            $ProxyCount = NULL;
            $RequesterID = NULL;
            $forceAuthn = TRUE;
            $isPassive = FALSE;
            $consumerURL = NULL;
            $consumerIndex = NULL;
            $extensions = NULL;

            SimpleSAML_Logger::info('SAML2.0 - IdP.SSOService: IdP initiated authentication: '. var_export($spEntityId, TRUE));

        } else {
            
            /* SP initiated authentication. */
            $binding = SAML2_Binding::getCurrentBinding();
            $request = $binding->receive();
            
            if (!($request instanceof SAML2_AuthnRequest)) {
                throw new SimpleSAML_Error_BadRequest('Message received on authentication request endpoint wasn\'t an authentication request.');
            }

            $spEntityId = $request->getIssuer();
            if ($spEntityId === NULL) {
                throw new SimpleSAML_Error_BadRequest('Received message on authentication request endpoint without issuer.');
            }

            sspmod_saml_Message::validateMessage($spMetadata, $idpMetadata, $request);

            $relayState = $request->getRelayState();

            $requestId = $request->getId();
            $IDPList = $request->getIDPList();
            $ProxyCount = $request->getProxyCount();
            if ($ProxyCount !== null) $ProxyCount--;
            $RequesterID = $request->getRequesterID();
            $forceAuthn = $request->getForceAuthn();
            $isPassive = $request->getIsPassive();
            $consumerURL = $request->getAssertionConsumerServiceURL();
            $protocolBinding = $request->getProtocolBinding();
            $consumerIndex = $request->getAssertionConsumerServiceIndex();
            $extensions = $request->getExtensions();
            $nameIdPolicy = $request->getNameIdPolicy();
            
            if (isset($nameIdPolicy['Format'])) {
                    $nameIDFormat = $nameIdPolicy['Format'];
            } else {
                    $nameIDFormat = NULL;
            }
            SimpleSAML_Logger::info('SAML2.0 - IdP.SSOService: Incomming Authentication request: '. var_export($spEntityId, TRUE));
        }
        
        $acsEndpoint = self::getAssertionConsumerService($supportedBindings, $spMetadata, $consumerURL, $protocolBinding, $consumerIndex);

        $IDPList = array_unique(array_merge($IDPList, $spMetadata->getArrayizeString('IDPList', array())));
        if ($ProxyCount == null) $ProxyCount = $spMetadata->getInteger('ProxyCount', null);

        if (!$forceAuthn) {
            $forceAuthn = $spMetadata->getBoolean('ForceAuthn', FALSE);
        }

        $sessionLostParams = array(
            'spentityid' => $spEntityId,
            'cookieTime' => time(),
        );
        if ($relayState !== NULL) {
            $sessionLostParams['RelayState'] = $relayState;
        }

        $sessionLostURL = SimpleSAML_Utilities::addURLparameter(
            SimpleSAML_Utilities::selfURLNoQuery(),
            $sessionLostParams);

        $state = array(
            'Responder' => array('sspmod_authinwebo_IdP_InWebo', 'sendResponse'),
            SimpleSAML_Auth_State::EXCEPTION_HANDLER_FUNC => array('sspmod_saml_IdP_SAML2', 'handleAuthError'),
            SimpleSAML_Auth_State::RESTART => $sessionLostURL,

            'SPMetadata' => $spMetadata->toArray(),
            'saml:RelayState' => $relayState,
            'saml:RequestId' => $requestId,
            'saml:IDPList' => $IDPList,
            'saml:ProxyCount' => $ProxyCount,
            'saml:RequesterID' => $RequesterID,
            'ForceAuthn' => $forceAuthn,
            'isPassive' => $isPassive,
            'saml:ConsumerURL' => $acsEndpoint['Location'],
            'saml:Binding' => $acsEndpoint['Binding'],
            'saml:NameIDFormat' => $nameIDFormat,
            'saml:Extensions' => $extensions,
        );

        $idp->handleAuthenticationRequest($state);
    }    
    
    
    /**
     * Fonction copiée à l'identique depuis la classe sspmod_saml_IdP_SAML2
     * 
     * pour pouvoir être utilisée localement (private) par la fonction custom de handle de request receiveAuthnRequest définie ci-dessus
     * 
     * Find SP AssertionConsumerService based on parameter in AuthnRequest.
     *
     * @param array $supportedBindings  The bindings we allow for the response.
     * @param SimpleSAML_Configuration $spMetadata  The metadata for the SP.
     * @param string|NULL $AssertionConsumerServiceURL  AssertionConsumerServiceURL from request.
     * @param string|NULL $ProtocolBinding  ProtocolBinding from request.
     * @param int|NULL $AssertionConsumerServiceIndex  AssertionConsumerServiceIndex from request.
     * @return array  Array with the Location and Binding we should use for the response.
     */
    private static function getAssertionConsumerService(array $supportedBindings, SimpleSAML_Configuration $spMetadata,
        $AssertionConsumerServiceURL, $ProtocolBinding, $AssertionConsumerServiceIndex) {
        assert('is_string($AssertionConsumerServiceURL) || is_null($AssertionConsumerServiceURL)');
        assert('is_string($ProtocolBinding) || is_null($ProtocolBinding)');
        assert('is_int($AssertionConsumerServiceIndex) || is_null($AssertionConsumerServiceIndex)');

        /* We want to pick the best matching endpoint in the case where for example
         * only the ProtocolBinding is given. We therefore pick endpoints with the
         * following priority:
         *  1. isDefault="true"
         *  2. isDefault unset
         *  3. isDefault="false"
         */
        $firstNotFalse = NULL;
        $firstFalse = NULL;
        foreach ($spMetadata->getEndpoints('AssertionConsumerService') as $ep) {

            if ($AssertionConsumerServiceURL !== NULL && $ep['Location'] !== $AssertionConsumerServiceURL) {
                continue;
            }
            if ($ProtocolBinding !== NULL && $ep['Binding'] !== $ProtocolBinding) {
                continue;
            }
            if ($AssertionConsumerServiceIndex !== NULL && $ep['index'] !== $AssertionConsumerServiceIndex) {
                continue;
            }

            if (!in_array($ep['Binding'], $supportedBindings, TRUE)) {
                /* The endpoint has an unsupported binding. */
                continue;
            }

            /* We have an endpoint that matches all our requirements. Check if it is the best one. */

            if (array_key_exists('isDefault', $ep)) {
                if ($ep['isDefault'] === TRUE) {
                        /* This is the first matching endpoint with isDefault set to TRUE. */
                        return $ep;
                }
                /* isDefault is set to FALSE, but the endpoint is still useable. */
                if ($firstFalse === NULL) {
                        /* This is the first endpoint that we can use. */
                        $firstFalse = $ep;
                }
            } else if ($firstNotFalse === NULL) {
                /* This is the first endpoint without isDefault set. */
                $firstNotFalse = $ep;
            }
        }

        if ($firstNotFalse !== NULL) {
                return $firstNotFalse;
        } elseif ($firstFalse !== NULL) {
                return $firstFalse;
        }

        SimpleSAML_Logger::warning('Authentication request specifies invalid AssertionConsumerService:');
        if ($AssertionConsumerServiceURL !== NULL) {
            SimpleSAML_Logger::warning('AssertionConsumerServiceURL: ' . var_export($AssertionConsumerServiceURL, TRUE));
        }
        if ($ProtocolBinding !== NULL) {
            SimpleSAML_Logger::warning('ProtocolBinding: ' . var_export($ProtocolBinding, TRUE));
        }
        if ($AssertionConsumerServiceIndex !== NULL) {
            SimpleSAML_Logger::warning('AssertionConsumerServiceIndex: ' . var_export($AssertionConsumerServiceIndex, TRUE));
        }

        /* We have no good endpoints. Our last resort is to just use the default endpoint. */
        return $spMetadata->getDefaultEndpoint('AssertionConsumerService', $supportedBindings);
    }
        
    /**
    * Fonction modifiée copiée depuis la classe sspmod_saml_IdP_SAML2
    * 
    * Send a response to the SP.
    *
    * @param array $state  The authentication state.
    */
    public static function sendResponse(array $state) {
        
            assert('isset($state["Attributes"])');
            assert('isset($state["SPMetadata"])');
            assert('isset($state["saml:ConsumerURL"])');
            assert('array_key_exists("saml:RequestId", $state)'); // Can be NULL.
            assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.

            $spMetadata = $state["SPMetadata"];
            $spEntityId = $spMetadata['entityid'];
            $spMetadata = SimpleSAML_Configuration::loadFromArray($spMetadata,
                    '$metadata[' . var_export($spEntityId, TRUE) . ']');

            SimpleSAML_Logger::info('Sending SAML 2.0 Response to ' . var_export($spEntityId, TRUE));

            $requestId = $state['saml:RequestId'];
            $relayState = $state['saml:RelayState'];
            $consumerURL = $state['saml:ConsumerURL'];
            $protocolBinding = $state['saml:Binding'];

            $idp = SimpleSAML_IdP::getByState($state);

            $idpMetadata = $idp->getConfig();

            $assertion = self::buildAssertion($idpMetadata, $spMetadata, $state); //// MODIF

            if (isset($state['saml:AuthenticatingAuthority'])) {
                    $assertion->setAuthenticatingAuthority($state['saml:AuthenticatingAuthority']);
            }

            /* Create the session association (for logout). */
            $association = array(
                    'id' => 'saml:' . $spEntityId,
                    'Handler' => 'sspmod_saml_IdP_SAML2',
                    'Expires' => $assertion->getSessionNotOnOrAfter(),
                    'saml:entityID' => $spEntityId,
                    'saml:NameID' => $state['saml:idp:NameID'],
                    'saml:SessionIndex' => $assertion->getSessionIndex(),
            );

            /* Maybe encrypt the assertion. */
            $assertion = self::encryptAssertion($idpMetadata, $spMetadata, $assertion);

            /* Create the response. */
            $ar = self::buildResponse($idpMetadata, $spMetadata, $consumerURL);
            $ar->setInResponseTo($requestId);
            $ar->setRelayState($relayState);
            $ar->setAssertions(array($assertion));

            /* Register the session association with the IdP. */
            $idp->addAssociation($association);

            SimpleSAML_Stats::log('saml:idp:Response', array(
                    'spEntityID' => $spEntityId,
                    'idpEntityID' => $idpMetadata->getString('entityid'),
                    'protocol' => 'saml2',
            ));

            /* Send the response. */
            $binding = SAML2_Binding::getBinding($protocolBinding);
            $binding->send($ar);
    }
        
    /**
    * Fonction modifiée copiée depuis la classe sspmod_saml_IdP_SAML2
    * 
    * Build an assertion based on information in the metadata.
    *
    * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
    * @param SimpleSAML_Configuration $spMetadata  The metadata of the SP.
    * @param array &$state  The state array with information about the request.
    * @return SAML2_Assertion  The assertion.
    */
    private static function buildAssertion(SimpleSAML_Configuration $idpMetadata,
        SimpleSAML_Configuration $spMetadata, array &$state) {
        assert('isset($state["Attributes"])');
        assert('isset($state["saml:ConsumerURL"])');

        $signAssertion = $spMetadata->getBoolean('saml20.sign.assertion', NULL);
        if ($signAssertion === NULL) {
                $signAssertion = $idpMetadata->getBoolean('saml20.sign.assertion', TRUE);
        }

        $config = SimpleSAML_Configuration::getInstance();

        $a = new SAML2_Assertion();
        if ($signAssertion) {
                self::addSign($idpMetadata, $spMetadata, $a); //////MODIF
        }

        $a->setIssuer($idpMetadata->getString('entityid'));
        $a->setValidAudiences(array($spMetadata->getString('entityid')));

        $a->setNotBefore(time() - 30);

        $assertionLifetime = $spMetadata->getInteger('assertion.lifetime', NULL);
        if ($assertionLifetime === NULL) {
                $assertionLifetime = $idpMetadata->getInteger('assertion.lifetime', 300);
        }
        $a->setNotOnOrAfter(time() + $assertionLifetime);

        if (isset($state['saml:AuthnContextClassRef'])) {
            $a->setAuthnContext($state['saml:AuthnContextClassRef']);
        } else {
            $a->setAuthnContext(SAML2_Const::AC_PASSWORD);
        }

        if (isset($state['AuthnInstant'])) {
            $a->setAuthnInstant($state['AuthnInstant']);
        } else {
            /* For backwards compatibility. Remove in version 1.8. */
            $session = SimpleSAML_Session::getInstance();
            $a->setAuthnInstant($session->getAuthnInstant());
        }

        $sessionLifetime = $config->getInteger('session.duration', 8*60*60);
        $a->setSessionNotOnOrAfter(time() + $sessionLifetime);

        $a->setSessionIndex(SimpleSAML_Utilities::generateID());

        $sc = new SAML2_XML_saml_SubjectConfirmation();
        $sc->SubjectConfirmationData = new SAML2_XML_saml_SubjectConfirmationData();
        $sc->SubjectConfirmationData->NotOnOrAfter = time() + $assertionLifetime;
        $sc->SubjectConfirmationData->Recipient = $state['saml:ConsumerURL'];
        $sc->SubjectConfirmationData->InResponseTo = $state['saml:RequestId'];

        /* ProtcolBinding of SP's <AuthnRequest> overwrites IdP hosted metadata configuration. */
        $hokAssertion = NULL;
        if ($state['saml:Binding'] === SAML2_Const::BINDING_HOK_SSO) {
            $hokAssertion = TRUE;
        }
        if ($hokAssertion === NULL) {
                $hokAssertion = $idpMetadata->getBoolean('saml20.hok.assertion', FALSE);
        }

        if ($hokAssertion) {
                /* Holder-of-Key */
                $sc->Method = SAML2_Const::CM_HOK;
                if (SimpleSAML_Utilities::isHTTPS()) {
                        if (isset($_SERVER['SSL_CLIENT_CERT']) && !empty($_SERVER['SSL_CLIENT_CERT'])) {
                                /* Extract certificate data (if this is a certificate). */
                                $clientCert = $_SERVER['SSL_CLIENT_CERT'];
                                $pattern = '/^-----BEGIN CERTIFICATE-----([^-]*)^-----END CERTIFICATE-----/m';
                                if (preg_match($pattern, $clientCert, $matches)) {
                                        /* We have a client certificate from the browser which we add to the HoK assertion. */
                                        $x509Certificate = new SAML2_XML_ds_X509Certificate();
                                        $x509Certificate->certificate = str_replace(array("\r", "\n", " "), '', $matches[1]);

                                        $x509Data = new SAML2_XML_ds_X509Data();
                                        $x509Data->data[] = $x509Certificate;

                                        $keyInfo = new SAML2_XML_ds_KeyInfo();
                                        $keyInfo->info[] = $x509Data;

                                        $sc->SubjectConfirmationData->info[] = $keyInfo;
                                } else throw new SimpleSAML_Error_Exception('Error creating HoK assertion: No valid client certificate provided during TLS handshake with IdP');
                        } else throw new SimpleSAML_Error_Exception('Error creating HoK assertion: No client certificate provided during TLS handshake with IdP');
                } else throw new SimpleSAML_Error_Exception('Error creating HoK assertion: No HTTPS connection to IdP, but required for Holder-of-Key SSO');
        } else {
                /* Bearer */
                $sc->Method = SAML2_Const::CM_BEARER;
        }
        $a->setSubjectConfirmation(array($sc));

        /* Add attributes. */
        if ($spMetadata->getBoolean('simplesaml.attributes', TRUE)) {
            $attributeNameFormat = self::getAttributeNameFormat($idpMetadata, $spMetadata);
            $a->setAttributeNameFormat($attributeNameFormat);
            $attributes = self::encodeAttributes($idpMetadata, $spMetadata, $state['Attributes']);
            $a->setAttributes($attributes);
        }
        
        /* Generate the NameID for the assertion. */         
        if (isset($state['saml:NameIDFormat'])) {
            //Si authentification Google Apps
            if (sspmod_authinwebo_InWebo::getSamlParameterInSession('saml_auth_type') == '2') {                
                $nameIdFormat = $spMetadata->getValue('NameIDFormat');
            //Si NameIDFormat spécifié dans les metadatas SP récupérées dans la config du connecteur
            } else if ($spMetadata->getValue('NameIDFormat') != '') {
                $nameIdFormat = $spMetadata->getValue('NameIDFormat');
            } else {
                $nameIdFormat = $state['saml:NameIDFormat'];
            }
        } else {
            //Si NameIDFormat spécifié dans les metadatas SP récupérées dans la config du connecteur
            if ($spMetadata->getValue('NameIDFormat') != '') {
                $nameIdFormat = $spMetadata->getValue('NameIDFormat');
            } else {
                $nameIdFormat = NULL;
            }
        }

        if ($nameIdFormat === NULL || !isset($state['saml:NameID'][$nameIdFormat])) {
            /* Either not set in request, or not set to a format we supply. Fall back to old generation method. */
            $nameIdFormat = $spMetadata->getString('NameIDFormat', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
        }

        if (isset($state['saml:NameID'][$nameIdFormat])) {
                $nameId = $state['saml:NameID'][$nameIdFormat];
                $nameId['Format'] = $nameIdFormat;
        } else {
                $spNameQualifier = $spMetadata->getString('SPNameQualifier', NULL);
                if ($spNameQualifier === NULL) {
                    $spNameQualifier = $spMetadata->getString('entityid');
                }

                if ($nameIdFormat === SAML2_Const::NAMEID_TRANSIENT) {
                    /* generate a random id */
                    $nameIdValue = SimpleSAML_Utilities::generateID();
                } else {
                    /* this code will end up generating either a fixed assigned id (via nameid.attribute)
                       or random id if not assigned/configured */
                    $nameIdValue = self::generateNameIdValue($idpMetadata, $spMetadata, $state);
                    
                    if ($nameIdValue === NULL) {
                            SimpleSAML_Logger::warning('Falling back to transient NameID.');
                            $nameIdFormat = SAML2_Const::NAMEID_TRANSIENT;
                            $nameIdValue = SimpleSAML_Utilities::generateID();
                    }
                }

                $nameId = array(
                    'Format' => $nameIdFormat,
                    'Value' => $nameIdValue,
                    'SPNameQualifier' => $spNameQualifier,
                );
        }

        $state['saml:idp:NameID'] = $nameId;

        $a->setNameId($nameId);

        $encryptNameId = $spMetadata->getBoolean('nameid.encryption', NULL);
        if ($encryptNameId === NULL) {
                $encryptNameId = $idpMetadata->getBoolean('nameid.encryption', FALSE);
        }
        if ($encryptNameId) {
                $a->encryptNameId(sspmod_saml_Message::getEncryptionKey($spMetadata));
        } 

        return $a;
    }
    
    /**
    * 
    * Fonction modifiée copiée depuis la classe sspmod_saml_Message
    * 
    * Add signature key and and senders certificate to an element (Message or Assertion).
    *
    * @param SimpleSAML_Configuration $srcMetadata  The metadata of the sender.
    * @param SimpleSAML_Configuration $dstMetadata  The metadata of the recipient.
    * @param SAML2_Message $element  The element we should add the data to.
    */
    public static function addSign(SimpleSAML_Configuration $srcMetadata, SimpleSAML_Configuration $dstMetadata = NULL, SAML2_SignedElement $element) {
        
        //Si un certificat connecteur existe en session
        if (sspmod_authinwebo_InWebo::getSamlParameterInSession('servicePem') !== null
            && sspmod_authinwebo_InWebo::getSamlParameterInSession('serviceCert') !== null) {    
            
            //Clé privée
            $keyArray = array('PEM' => sspmod_authinwebo_InWebo::getSamlParameterInSession('servicePem'));
            
            //Clé publique
            $pem = sspmod_authinwebo_InWebo::getSamlParameterInSession('serviceCert');
            
            $certData = $pem;
            $certData1 = preg_replace('/\n/','', $certData);
            $certData2 = preg_replace('/\r/','', $certData1);
            $certData3 = preg_replace('/-----BEGIN CERTIFICATE-----/','', $certData2);
            $certData4 = preg_replace('/-----END CERTIFICATE-----/','', $certData3);
            
            $certFingerprint = strtolower(sha1(base64_decode($certData4)));
            
            $certArray = array( 
                    'certData' => $certData4,
                    'PEM' => $pem,
                    'certFingerprint' => array($certFingerprint));
        } else {
           $keyArray = SimpleSAML_Utilities::loadPrivateKey($srcMetadata, TRUE);
           $certArray = SimpleSAML_Utilities::loadPublicKey($srcMetadata, FALSE);
        }

        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        if (array_key_exists('password', $keyArray)) {
                $privateKey->passphrase = $keyArray['password'];
        }
        $privateKey->loadKey($keyArray['PEM'], FALSE);
        $element->setSignatureKey($privateKey);

        if ($certArray === NULL) {
                /* We don't have a certificate to add. */
                return;
        }
        
        if (!array_key_exists('PEM', $certArray)) {
                /* We have a public key with only a fingerprint. */
                return;
        }

        $element->setCertificates(array($certArray['PEM']));
    }
    
    /**
    * Fonction copiée à l'identique depuis la classe sspmod_saml_IdP_SAML2
    * 
    * Encrypt an assertion.
    *
    * This function takes in a SAML2_Assertion and encrypts it if encryption of
    * assertions are enabled in the metadata.
    *
    * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
    * @param SimpleSAML_Configuration $spMetadata  The metadata of the SP.
    * @param SAML2_Assertion $assertion  The assertion we are encrypting.
    * @return SAML2_Assertion|SAML2_EncryptedAssertion  The assertion.
    */
    private static function encryptAssertion(SimpleSAML_Configuration $idpMetadata,
        SimpleSAML_Configuration $spMetadata, SAML2_Assertion $assertion) {

        $encryptAssertion = $spMetadata->getBoolean('assertion.encryption', NULL);
        if ($encryptAssertion === NULL) {
                $encryptAssertion = $idpMetadata->getBoolean('assertion.encryption', FALSE);
        }
        if (!$encryptAssertion) {
                /* We are _not_ encrypting this assertion, and are therefore done. */
                return $assertion;
        }

        $sharedKey = $spMetadata->getString('sharedkey', NULL);
        if ($sharedKey !== NULL) {
                $key = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
                $key->loadKey($sharedKey);
        } else {
                $keys = $spMetadata->getPublicKeys('encryption', TRUE);
                $key = $keys[0];
                switch ($key['type']) {
                case 'X509Certificate':
                        $pemKey = "-----BEGIN CERTIFICATE-----\n" .
                                chunk_split($key['X509Certificate'], 64) .
                                "-----END CERTIFICATE-----\n";
                        break;
                default:
                        throw new SimpleSAML_Error_Exception('Unsupported encryption key type: ' . $key['type']);
                }

                /* Extract the public key from the certificate for encryption. */
                $key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'public'));
                $key->loadKey($pemKey);
        }

        $ea = new SAML2_EncryptedAssertion();
        $ea->setAssertion($assertion, $key);
        return $ea;
    }

    /**
     * Fonction copiée à l'identique depuis la classe sspmod_saml_IdP_SAML2
     * 
     * Build a authentication response based on information in the metadata.
     *
     * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
     * @param SimpleSAML_Configuration $spMetadata  The metadata of the SP.
     * @param string $consumerURL  The Destination URL of the response.
     */
    private static function buildResponse(SimpleSAML_Configuration $idpMetadata, SimpleSAML_Configuration $spMetadata, $consumerURL) {
        $signResponse = $spMetadata->getBoolean('saml20.sign.response', NULL);
        if ($signResponse === NULL) {
            $signResponse = $idpMetadata->getBoolean('saml20.sign.response', TRUE);
        }

        $r = new SAML2_Response();
        
        $saml_auth_type = sspmod_authinwebo_InWebo::getSamlParameterInSession('saml_auth_type');
        
        //If Google Apps authentication
        if ($saml_auth_type !== null && $saml_auth_type == '2') { 
            //Issuer is the Google Apps domain
            $r->setIssuer(sspmod_authinwebo_InWebo::getSamlParameterInSession('gappsDomain'));
        } else {
            $r->setIssuer($idpMetadata->getString('entityid'));
        }
        
        $r->setDestination($consumerURL);

        if ($signResponse) {
            self::addSign($idpMetadata, $spMetadata, $r);
        }

        return $r;
    }

    /**
    * 
    * Fonction copiée à l'identique depuis la classe sspmod_saml_IdP_SAML2
    * 
    * Helper function for encoding attributes.
    *
    * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
    * @param SimpleSAML_Configuration $spMetadata  The metadata of the SP.
    * @param array $attributes  The attributes of the user
    * @return array  The encoded attributes.
    */
    private static function encodeAttributes(SimpleSAML_Configuration $idpMetadata,
           SimpleSAML_Configuration $spMetadata, array $attributes) {

           $base64Attributes = $spMetadata->getBoolean('base64attributes', NULL);
           if ($base64Attributes === NULL) {
                   $base64Attributes = $idpMetadata->getBoolean('base64attributes', FALSE);
           }

           if ($base64Attributes) {
                   $defaultEncoding = 'base64';
           } else {
                   $defaultEncoding = 'string';
           }

           $srcEncodings = $idpMetadata->getArray('attributeencodings', array());
           $dstEncodings = $spMetadata->getArray('attributeencodings', array());

           /*
            * Merge the two encoding arrays. Encodings specified in the target metadata
            * takes precedence over the source metadata.
            */
           $encodings = array_merge($srcEncodings, $dstEncodings);

           $ret = array();

           foreach ($attributes as $name => $values) {
                   $ret[$name] = array();
                   if (array_key_exists($name, $encodings)) {
                           $encoding = $encodings[$name];
                   } else {
                           $encoding = $defaultEncoding;
                   }

                   foreach ($values as $value) {
                           switch ($encoding) {
                           case 'string':
                                   $value = (string)$value;
                                   break;
                           case 'base64':
                                   $value = base64_encode((string)$value);
                                   break;
                           case 'raw':
                                   if (is_string($value)) {
                                           $doc = new DOMDocument();
                                           $doc->loadXML('<root>' . $value . '</root>');
                                           $value = $doc->firstChild->childNodes;
                                   }
                                   assert('$value instanceof DOMNodeList');
                                   break;
                           default:
                                   throw new SimpleSAML_Error_Exception('Invalid encoding for attribute ' .
                                           var_export($name, TRUE) . ': ' . var_export($encoding, TRUE));
                           }
                           $ret[$name][] = $value;
                   }
           }

           return $ret;
    }

    /**
    * 
    * Fonction copiée à l'identique depuis la classe sspmod_saml_IdP_SAML2
    * 
    * Determine which NameFormat we should use for attributes.
    *
    * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
    * @param SimpleSAML_Configuration $spMetadata  The metadata of the SP.
    * @return string  The NameFormat.
    */
    private static function getAttributeNameFormat(SimpleSAML_Configuration $idpMetadata, SimpleSAML_Configuration $spMetadata) {

           /* Try SP metadata first. */
           $attributeNameFormat = $spMetadata->getString('attributes.NameFormat', NULL);
           if ($attributeNameFormat !== NULL) {
                   return $attributeNameFormat;
           }
           $attributeNameFormat = $spMetadata->getString('AttributeNameFormat', NULL);
           if ($attributeNameFormat !== NULL) {
                   return $attributeNameFormat;
           }

           /* Look in IdP metadata. */
           $attributeNameFormat = $idpMetadata->getString('attributes.NameFormat', NULL);
           if ($attributeNameFormat !== NULL) {
                   return $attributeNameFormat;
           }
           $attributeNameFormat = $idpMetadata->getString('AttributeNameFormat', NULL);
           if ($attributeNameFormat !== NULL) {
                   return $attributeNameFormat;
           }

           /* Default. */
           return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
    }
    
    /**
    * Calculate the NameID value that should be used.
    *
    * @param SimpleSAML_Configuration $idpMetadata  The metadata of the IdP.
    * @param SimpleSAML_Configuration $dstMetadata  The metadata of the SP.
    * @param array &$state  The authentication state of the user.
    * @return string  The NameID value.
    */
    private static function generateNameIdValue(SimpleSAML_Configuration $idpMetadata,
        SimpleSAML_Configuration $spMetadata, array &$state) {

        $attribute = $spMetadata->getString('simplesaml.nameidattribute', NULL);
        if ($attribute === NULL) {
            $attribute = $idpMetadata->getString('simplesaml.nameidattribute', NULL);
            if ($attribute === NULL) {
                if (!isset($state['UserID'])) {
                        SimpleSAML_Logger::error('Unable to generate NameID. Check the userid.attribute option.');
                }
                $attributeValue = $state['UserID'];
                $idpEntityId = $idpMetadata->getString('entityid');
                $spEntityId = $spMetadata->getString('entityid');

                $secretSalt = SimpleSAML_Utilities::getSecretSalt();

                $uidData = 'uidhashbase' . $secretSalt;
                $uidData .= strlen($idpEntityId) . ':' . $idpEntityId;
                $uidData .= strlen($spEntityId) . ':' . $spEntityId;
                $uidData .= strlen($attributeValue) . ':' . $attributeValue;
                $uidData .= $secretSalt;

                return hash('sha1', $uidData);
            }
        }

        $attributes = $state['Attributes'];
        if (!array_key_exists($attribute, $attributes)) {
                SimpleSAML_Logger::error('Unable to add NameID: Missing ' . var_export($attribute, TRUE) .
                        ' in the attributes of the user.');
                return NULL;
        }
        return $attributes[$attribute][0];
    }
    
    /**
     * Version modifiée de la fonction receiveLogoutMessage de la classe simpleSAML sspmod_saml_IdP_SAML2
     * Appelée depuis le contrôleur Symfony du favori SAML, action LogoutPage
     * 
     * Receive a logout message.
     *
     * @param SimpleSAML_IdP $idp  The IdP we are receiving it for.
     * @param SimpleSAML_Configuration $spMetadata The SP metadata loaded from the In-Webo SAML Generic connector in the Symfony Controller
     * 
     */
    public static function receiveLogoutMessage(SimpleSAML_IdP $idp, SimpleSAML_Configuration $spMetadata) {

        $binding = SAML2_Binding::getCurrentBinding();
        $message = $binding->receive();

        $spEntityId = $message->getIssuer();
        if ($spEntityId === NULL) {
            /* Without an issuer we have no way to respond to the message. */
            throw new SimpleSAML_Error_BadRequest('Received message on logout endpoint without issuer.');
        }

        $idpMetadata = $idp->getConfig();
        $spMetadata = $spMetadata;

        sspmod_saml_Message::validateMessage($spMetadata, $idpMetadata, $message);

        if ($message instanceof SAML2_LogoutResponse) {               

            SimpleSAML_Logger::info('Received SAML 2.0 LogoutResponse from: '. var_export($spEntityId, TRUE));

            $relayState = $message->getRelayState();

            if (!$message->isSuccess()) {
                    $logoutError = sspmod_saml_Message::getResponseError($message);
                    SimpleSAML_Logger::warning('Unsuccessful logout. Status was: ' . $logoutError);
            } else {
                    $logoutError = NULL;
            }

            $assocId = 'saml:' . $spEntityId;

            $idp->handleLogoutResponse($assocId, $relayState, $logoutError);


        } elseif ($message instanceof SAML2_LogoutRequest) {

            SimpleSAML_Logger::info('Received SAML 2.0 LogoutRequest from: '. var_export($spEntityId, TRUE));

            $spStatsId = $spMetadata->getString('core:statistics-id', $spEntityId);

            SimpleSAML_Logger::stats('saml20-idp-SLO spinit ' . $spStatsId . ' ' . $idpMetadata->getString('entityid'));

            $state = array(
                'Responder' => array('sspmod_authinwebo_IdP_InWebo', 'sendLogoutResponse'),// MODIF On définit ici notre fonction custom d'envoi de réponse logout
                'saml:SPEntityId' => $spEntityId,
                'saml:SPMetadata' => $spMetadata, //On passe les metadata du SP ici
                'saml:RelayState' => $message->getRelayState(),
                'saml:RequestId' => $message->getId(),
            );

            $assocId = 'saml:' . $spEntityId;
            $idp->handleLogoutRequest($state, $assocId);

        } else {
            throw new SimpleSAML_Error_BadRequest('Unknown message received on logout endpoint: ' . get_class($message));
        }
    }

    /**
     * Version modifiée de la fonction sendLogoutResponse de la classe simpleSAML sspmod_saml_IdP_SAML2
     * Appelée depuis la fonction ci-dessus : receiveLogoutMessage
     * Les metadata du SP récupérée dans le tableau $state, clé saml:SPMetadata
     *
     * @param array &$state  The logout state array.
     */
    public static function sendLogoutResponse(SimpleSAML_IdP $idp, array $state) {

        assert('isset($state["saml:SPEntityId"])');
        assert('isset($state["saml:RequestId"])');
        assert('isset($state["saml:SPMetadata"])');
        assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.

        $spEntityId = $state['saml:SPEntityId'];

        $idpMetadata = $idp->getConfig();
        $spMetadata = $state["saml:SPMetadata"];

        $lr = sspmod_saml_Message::buildLogoutResponse($idpMetadata, $spMetadata);
        $lr->setInResponseTo($state['saml:RequestId']);
        $lr->setRelayState($state['saml:RelayState']);

        if (isset($state['core:Failed']) && $state['core:Failed']) {
                $lr->setStatus(array(
                    'Code' => SAML2_Const::STATUS_SUCCESS,
                    'SubCode' => SAML2_Const::STATUS_PARTIAL_LOGOUT,
                ));
                SimpleSAML_Logger::info('Sending logout response for partial logout to SP ' . var_export($spEntityId, TRUE));
        } else {
                SimpleSAML_Logger::debug('Sending logout response to SP ' . var_export($spEntityId, TRUE));
        }

        $binding = new SAML2_HTTPRedirect();
        $binding->send($lr);                
    }
}
