<?php

namespace CommerceGuys\Guzzle\Oauth2\GrantType;

use CommerceGuys\Guzzle\Oauth2\AccessToken;
use Doctrine\Common\Cache\Cache;

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
     * @param Cache $cache
     *
     * @return mixed
     */
    public function setCache(Cache $cache);
}
