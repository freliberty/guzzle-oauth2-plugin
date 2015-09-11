<?php

namespace CommerceGuys\Guzzle\Oauth2\GrantType;

use CommerceGuys\Guzzle\Oauth2\AccessToken;


interface GrantTypeInterface
{
    /**
     * Get the token data returned by the OAuth2 server.
     *
     * @param bool $forcecache
     *
     * @return AccessToken
     */
    public function getToken($forcecache = false);

    /**
     * @param $cache
     *
     * @return mixed
     */
    public function setCache($cache);
}
