<?php

/**
 * InWebo SAML 2.0 authentication external authentication source.
 *
 * (c) inWebo 2013-2014
 * 
 * Compatible with SimpleSAML 1.9
 * 
 */

class sspmod_authinwebo_Auth_Source_InWebo extends SimpleSAML_Auth_Source {

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
     public function __construct($info, $config) {
            assert('is_array($info)');
            assert('is_array($config)');

            /* Call the parent constructor first, as required by the interface. */
            parent::__construct($info, $config);
    }

    /**
     * Retrieve attributes for the user.
     *
     * @return array|NULL  The user's attributes, or NULL if the user isn't authenticated.
     */
     private function getUser() {
        if (!session_id()) {
            /* session_start not called before. Do it here. */
            session_start();
        }

        if (sspmod_authinwebo_InWebo::getSamlAttributeParameterInSession('uid') === null) {
            /* The user isn't authenticated. */
            return NULL;
        }

        /* Add attributes to the user */
        $attributes = array();
        $session_attributes = sspmod_authinwebo_InWebo::getSamlAttributesParametersInSession();
        
        if (!empty($session_attributes)) {
            foreach ($session_attributes as $attribute => $value) {
                if (sspmod_authinwebo_InWebo::getSamlAttributeParameterInSession($attribute) !== null && !in_array($attribute, $attributes)) {
                    if (!is_array($value)) {
                        $attributes[$attribute] = sspmod_authinwebo_InWebo::getSamlAttributeParameterInSession($attribute, 1);
                    } else {
                        $attributes[$attribute] = sspmod_authinwebo_InWebo::getSamlAttributeParameterInSession($attribute, 0);
                    }
                }
            }
        }

        return $attributes;
    }

    /**
     * Log in using an external authentication helper.
     *
     * @param array &$state  Information about the current authentication.
     */
     public function authenticate(&$state) {
        assert('is_array($state)');

        if (!(isset($state['ForceAuthn']) && $state['ForceAuthn'] == true)) {
            $attributes = $this->getUser();
            if ($attributes['uid'] !== NULL) {
                /*The user is already authenticated */
                $state['Attributes'] = $attributes;
                return;
            }
        } else {
            //On supprime les infos (attributs) du user authentifié en session
            sspmod_authinwebo_InWebo::clearSamlParametersInSession();
        }
        
        /*  The user isn't authenticated */

        /*
         * First we add the identifier of this authentication source
         * to the state array, so that we know where to resume.
         */
        $state['inwebo:AuthID'] = $this->authId;

        /* We need to save the $state-array, so that we can resume the
         * login process after authentication */
        $stateId = SimpleSAML_Auth_State::saveState($state, 'authinwebo:InWebo');

        /* Now we generate an URL the user should return to after authentication */
        $returnTo = sspmod_authinwebo_InWebo::getInWeboModuleURL('/saml2/resume', array(
            'State' => $stateId,
        ));
        
        /* Build the URL of the authentication page */
        $saml_auth_type = sspmod_authinwebo_InWebo::getSamlParameterInSession('saml_auth_type');
        
        //Forcing session saving before redirection (better than doing it on script exit)
        $session = \SimpleSAML_Session::getInstance();
        $session->saveSession();

        //If SAML 2 Juniper authentication
        if ($saml_auth_type !== null && $saml_auth_type == '9') { 
            
            $bookmarkAlias = sspmod_authinwebo_InWebo::getSamlParameterInSession('bookmarkAlias');
            $browserLanguage = sspmod_authinwebo_InWebo::getSamlParameterInSession('browserLanguage');
            $currentDevice = sspmod_authinwebo_InWebo::getSamlParameterInSession('currentDevice');
            $sid = sspmod_authinwebo_InWebo::getSamlParameterInSession('sid');
            
            if ($browserLanguage === null) { $browserLanguage = 'en'; }
            
            if ($bookmarkAlias !== null) {
                $authPath = '/j/' . $sid
                 . '/webapp/ult?action=authenticate&previous=&noiframe=1&referrer=' . $bookmarkAlias
                 . '&lang=' . $browserLanguage
                 . '&logo=1&iwlib=minify&verbose=0&maincolor=%23888888&skin=mobile&displaytype=inline&actiontitle=1&show_profiles=0'
                 . '&device=' . $currentDevice;

                $authPage = sspmod_authinwebo_InWebo::getInWeboHeliumURL($authPath);
                $authPostPage = sspmod_authinwebo_InWebo::getInWeboModuleURL('/saml2/auth');

                /* Redirect to the authentication page */
                SimpleSAML_Utilities::redirect($authPage, array('SamlReturnTo' => $returnTo, 'SamlAuthUrl' => $authPostPage));
                
            } else {
                $authPage = sspmod_authinwebo_InWebo::getInWeboModuleURL('/saml2/auth');
                /* Redirect to the authentication page */
                SimpleSAML_Utilities::redirect($authPage, array('ReturnTo' => $returnTo));
            }
            
        //Any other authentication   
        } else {
            $authPage = sspmod_authinwebo_InWebo::getInWeboModuleURL('/saml2/auth');
            /* Redirect to the authentication page */
            SimpleSAML_Utilities::redirect($authPage, array('ReturnTo' => $returnTo));
        }

        /* The redirect function never returns, so we never get this far */
        assert('FALSE');
    }


    /**
     * Resume authentication process.
     *
     * This function resumes the authentication process after the user has
     * entered his or her credentials.
     *
     * @param array &$state  The authentication state.
     */
     public static function resume() {

        /*
         * First we need to restore the $state-array. We should have the identifier for
         * it in the 'State' request parameter.
         */
        if (!isset($_REQUEST['State'])) {
            throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
        }
        $stateId = (string)$_REQUEST['State'];

        /*
         * Once again, note the second parameter to the loadState function. This must
         * match the string we used in the saveState-call above.
         */
        $state = SimpleSAML_Auth_State::loadState($stateId, 'authinwebo:InWebo');

        /*
         * Now we have the $state-array, and can use it to locate the authentication
         * source.
         */
        $source = SimpleSAML_Auth_Source::getById($state['inwebo:AuthID']);
        if ($source === NULL) {
            throw new SimpleSAML_Error_Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        /*
         * Make sure that we haven't switched the source type while the
         * user was at the authentication page.
         */
        if (!($source instanceof self)) {
            throw new SimpleSAML_Error_Exception('Authentication source type changed.');
        }

        /* First we check that the user is actually logged in, and didn't simply skip the login page */
        $attributes = $source->getUser();

        if ($attributes === NULL) {
            /* The user isn't authenticated */
            throw new SimpleSAML_Error_Exception('User not authenticated after login page.');
        }

        /*
         * So, we have a valid user. Time to resume the authentication process where we
         * paused it in the authenticate()-function above.
         */
        
        //Forcing session saving before redirection (better than doing it on script exit)
        $session = \SimpleSAML_Session::getInstance();
        $session->saveSession();

        $state['Attributes'] = $attributes;
        SimpleSAML_Auth_Source::completeAuth($state);

        /*
         * The completeAuth-function never returns, so we never get this far.
         */
        assert('FALSE');
    }
}
