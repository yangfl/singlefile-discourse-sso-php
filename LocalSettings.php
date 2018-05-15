<?php

// Forbid account creation by users
$wgGroupPermissions['*']['createaccount'] = false;
// Allow extensions to manage users
$wgGroupPermissions['*']['autocreateaccount'] = true;

require_once( "$IP/discourse-sso.php" );
$DISCOURSE_SSO = new DiscourseSSOClient();
$SSO_STATUS = $DISCOURSE_SSO->getAuthentication('https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
if ($SSO_STATUS['logged'] && !empty($SSO_STATUS['data']['target_username'])) {
    $wgAuthRemoteuserUserName = $SSO_STATUS['data']['target_username'];
    $wgAuthRemoteuserUserPrefsForced['email'] = $SSO_STATUS['data']['email'];
    $wgAuthRemoteuserUserPrefs['realname'] = $SSO_STATUS['data']['name'];
}

$wgAuthRemoteuserAllowUserSwitch = true;
$wgAuthRemoteuserUserUrls = [
    'logout' => '/discourse-sso.php?logout'
];

$wgHooks['PersonalUrls'][] = function (array &$personal_urls, Title $title, SkinTemplate $skin) {
    if (array_key_exists('login', $personal_urls)) {
        $personal_urls['login']['href'] ='/discourse-sso.php';
    }
};


