<?php

$metadata['idp-simplesaml'] = array(
        'UIInfo' => array(
            'DisplayName' => array(
                'en' => 'idp-simplesaml ',
                'es' => 'idp-simplesaml ',
                'gl' => 'idp-simplesaml ',
                'eu' => 'idp-simplesaml ',
                'ca' => 'idp-simplesaml ',
            ),
            'Description' => array(
                'en' => 'idp-simplesaml',
                'es' => 'idp-simplesaml',
                'gl' => 'idp-simplesaml',
                'eu' => 'idp-simplesaml',
                'ca' => 'idp-simplesaml',
            ),
            'InformationURL' => array(
                'en' => 'simplesaml',
                'es' => 'simplesaml',
                'gl' => 'simplesaml',
                'eu' => 'simplesaml',
                'ca' => 'simplesaml',
            ),
            'Domain' => array(
                'en' => 'idp-simplesaml',
                'es' => 'idp-simplesaml',
                'gl' => 'idp-simplesaml',
                'eu' => 'idp-simplesaml',
                'ca' => 'idp-simplesaml',
            ),
        ),
        'host' => '__DEFAULT__',
        'privatekey' => 'simplesaml.key.pem',
        'certificate' => 'simplesaml.crt.pem',
        'auth' => '',
        'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
       	'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
		'attributes' => array(
                'eduPersonTargetedID',
                'eduPersonAffiliation',
                'schacHomeOrganization',
                'eduPersonEntitlement',
                'schacPersonalUniqueCode',
                'uid',
                'mail',
                'displayName',
                'commonName',
                'eduPersonScopedAffiliation',
                'eduPersonPrincipalName',
                'schacHomeOrganizationType',
        ), 
        'authproc' => array(
            1 => array('class' => 'core:PHP','code' => '$attributes["LegacyTargetedId"] = array(md5($attributes["mail"][0]."SIR"));'),
            25 => array('class' => 'core:GenerateGroups', 'eduPersonAffiliation'),
            27 => array('class' => 'core:PHP','code' => '$attributes["schacPersonalUniqueCode"] = array("urn:mace:terena.org:schac:personalUniqueCode:es:ciemat:sir:mbid:{md5}".md5($attributes["mail"][0]));'),
            45 => array(
			 'class' => 'core:AttributeCopy',
			 'givenName' => array('cn','displayName'),
			) ,
            48 => array('class' => 'core:AttributeCopy','LegacyTargetedId' => 'eduPersonTargetedID'),
            50 => 'core:AttributeLimit',
            52 => array(
             'class' => 'core:AttributeAdd',
             'urn:oid:2.5.4.10' => 'idp-simplesaml',
             'urn:oid:1.3.6.1.4.1.25178.1.2.9' => array('idp-simplesaml'),
             'urn:oid:1.3.6.1.4.1.25178.1.2.10' => array('urn:schac:homeOrganizationType:es:pri'), 
             ),
            53 => array(
			 'class' => 'core:AttributeAdd',
			 'eduPersonEntitlement' => array('urn:mace:dir:entitlement:common-lib-terms'),
			),
            54 => array(
             'class' => 'core:ScopeAttribute',
             'scopeAttribute' => 'urn:oid:1.3.6.1.4.1.25178.1.2.9',
             'sourceAttribute' => 'uid',
             'targetAttribute' => 'eduPersonPrincipalName',
            ),
            55 => array(
             'class' => 'core:ScopeAttribute',
             'scopeAttribute' => 'eduPersonPrincipalName',
             'sourceAttribute' => 'eduPersonAffiliation',
             'targetAttribute' => 'eduPersonScopedAffiliation',
            ),
            100 => array('class' => 'core:AttributeMap', 'name2oid'),
        ),
        'assertion.encryption' => true
    );