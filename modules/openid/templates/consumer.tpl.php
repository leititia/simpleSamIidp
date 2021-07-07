<link rel="stylesheet" type="text/css" href="assets/css/openid.css">


<?php if ( !empty($this->data['error'])) { ?>
    <div class="error"><?php echo $this->data['error']; ?></div>
    <?php } ?>

    <form method="get" action="consumer.php">
        <fieldset>
            <legend>OpenID Login</legend>

            Identity&nbsp;URL:
            <input type="hidden" name="action" value="verify" />
            <input id="openid-identifier" class="openid-identifier" type="text" name="openid_url" value="http://" />
            <br>
            <br>
            <br>
            <!-- Email&nbsp;
            <input type="text" name="login_hint" > -->
            <input type="hidden" name="AuthState" value="<?php echo htmlspecialchars($this->data['AuthState'], ENT_QUOTES, 'UTF-8', 'html'); ?>" />
            <input type="submit" value="Login with OpenID" />
        </fieldset>
    </form>

    <p style="margin-top: 2em">
       OpenID is a free and easy way to use a single digital identity across the Internet. Enter your OpenID identity URL in the box above to authenticate.
    </p>
