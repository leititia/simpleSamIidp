<?php

namespace SimpleSAML\Module\openidprovider\Auth\Source\Auth\OpenID;

use SimpleSAML\Utils;

/**
 * Functions & helpers for InWebo SAML 2.0 authentication.
 *
 * (c) inWebo 2013-2014
 * 
 * Compatible with SimpleSAML 1.9
 * 
 */

class sspmod_authinwebo_InWebo {

    //Constants - Name ID Formats supported by inWebo IdP
    
    //Unspecified NameID format.
    const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    //Persistent NameID format.
    const NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    //Transient NameID format.
    const NAMEID_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    
    //Email Address NameID format.
    const NAMEID_EMAILADDRESS = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    
    //Session parameters manipulations
    
    public static function getSamlParametersInSession() {
        if (isset($_SESSION['samlParams']) && is_array($_SESSION['samlParams'])) {
            return $_SESSION['samlParams'];
        } else {
            return array();
        }
    }
    
    public static function getSamlAttributesParametersInSession() {
        if (isset($_SESSION['samlParams']['attributes']) && is_array($_SESSION['samlParams']['attributes'])) {
            return $_SESSION['samlParams']['attributes'];
        } else {
            return array();
        }
    }

    public static function clearSamlParametersInSession($all = 0) {
        if (isset($_SESSION['samlParams']) && is_array($_SESSION['samlParams'])) {
            if ($all == 1) {
                unset ($_SESSION['samlParams']);
            } else {
                unset($_SESSION['samlParams']['attributes']);
                unset($_SESSION['samlParams']['serviceCert']);
                unset($_SESSION['samlParams']['servicePem']);
            }
        }
    }

    public static function getSamlParameterInSession($param, $as_array = 0) {
        $iwparams = self::getSamlParametersInSession();

        if (!empty($iwparams)) {
            if (isset($iwparams[$param])) {
                if ($as_array == 1) {
                    return array($iwparams[$param]);                         
                } else {
                    return $iwparams[$param]; 
                }
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    public static function getSamlAttributeParameterInSession($param, $as_array = 0) {
        $iwparams = self::getSamlAttributesParametersInSession();

        if (!empty($iwparams)) {
            if (isset($iwparams[$param])) {
                if ($as_array == 1) {
                    return array($iwparams[$param]);                         
                } else {
                    return $iwparams[$param]; 
                }
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    /**
     * Retrieve the In-Webo service id stored in session.
     *
     * @return $sid or NULL if there is no service id in session.
     */
     public static function getIWServiceId() {

        if (self::getSamlParameterInSession('sid') === null) {
            /* No service id in the session. */
            return NULL;
        } else {
            return self::getSamlParameterInSession('sid');
        }

    }

    /**
     * Retrieve the In-Webo Symfony base URL stored in session.
     *
     * @return $url or NULL if there is no URL in session.
     */
     public static function getIWSymfonyBaseURL() {

        if (self::getSamlParameterInSession('symfonyURL') === null) {
            return NULL;
        } else {
            return self::getSamlParameterInSession('symfonyURL');
        }
    }
    
    /**
     * Retrieve the In-Webo Helium URL stored in session.
     *
     * @return $url or NULL if there is no URL in session.
     */
     public static function getIWHeliumBaseURL() {

        if (self::getSamlParameterInSession('heliumURL') === null) {
            return NULL;
        } else {
            return self::getSamlParameterInSession('heliumURL');
        }
    }

    /**
     * Retrieve the In-Webo Symfony service path in the current URL stored in session.
     *
     * @return $url or NULL if there is no path in session.
     */
     public static function getIWSymfonyServicePath() {

        if (self::getSamlParameterInSession('servicePath') === null) {
            return NULL;
        } else {
            return self::getSamlParameterInSession('servicePath');
        }
    }

    /**
     * Get absolute URL to a specified In-Webo Symfony based resource.
     *
     * This function creates an absolute URL to a resource stored under Symfony 2 path "/application...".
     *
     * @param string $resource  Resource path, on the form "<module name>/<resource>"
     * @param array $parameters  Extra parameters which should be added to the URL. Optional.
     * @return string  The absolute URL to the given resource.
     */
     public static function getInWeboModuleURL($resource, array $parameters = array()) {
        assert('is_string($resource)');

        $url = self::getIWSymfonyBaseURL() . $resource;
        if (!empty($parameters)) {
            $url = Utils\HTTP::addURLparameters($url, $parameters);
        }
        return $url;
    }
    
    public static function getInWeboHeliumURL($resource, array $parameters = array()) {
        assert('is_string($resource)');

        $url = self::getIWHeliumBaseURL() . $resource;
        if (!empty($parameters)) {
            $url = Utils\HTTP::addURLparameters($url, $parameters);
        }
        return $url;
    }
    
}
