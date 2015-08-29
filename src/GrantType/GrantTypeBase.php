<?php

namespace CommerceGuys\Guzzle\Oauth2\GrantType;

use CommerceGuys\Guzzle\Oauth2\AccessToken;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Collection;
use Doctrine\Common\Cache\Cache;

abstract class GrantTypeBase implements GrantTypeInterface
{
    /** @var ClientInterface The token endpoint client */
    protected $client;

    /** @var Collection Configuration settings */
    protected $config;

    /** @var string */
    protected $grantType = '';

    /** @var  Cache */
    protected $cache;

    /**
     * @param ClientInterface $client
     * @param array           $config
     */
    public function __construct(ClientInterface $client, array $config = [])
    {
        $this->client = $client;
        $this->config = Collection::fromConfig($config, $this->getDefaults(), $this->getRequired());
    }

    /**
     * @param Cache $cache
     */
    public function setCache(Cache $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Get default configuration items.
     *
     * @return array
     */
    protected function getDefaults()
    {
        return [
            'client_secret' => '',
            'scope' => '',
            'token_url' => 'oauth2/token',
            'auth_location' => 'headers',
        ];
    }

    /**
     * Get required configuration items.
     *
     * @return string[]
     */
    protected function getRequired()
    {
        return ['client_id'];
    }

    /**
     * Get additional options, if any.
     *
     * @return array|null
     */
    protected function getAdditionalOptions()
    {
        return null;
    }

    /**
     * @param bool|false $forcecache
     *
     * @return AccessToken
     */
    public function getToken($forcecache = false)
    {
        $config = $this->config->toArray();

        if ($this->cache) {
            $key = $this->getCacheKey($config);

            if ($forcecache || !$data = $this->cache->fetch($key)) { //cache missed

                $data = $this->getTokenDatas($config);

                $lifetime = 0;
                if (isset($data['expires'])) {
                    $lifetime = (int) $data['expires'] - time();
                    unset($data['expires']);
                } elseif (isset($data['expires_in'])) {
                    $lifetime = (int) $data['expires_in'];
                    unset($data['expires_in']);
                }

                if ($lifetime > 0) { //we remove 2sec on lifetime to be sure that cache is invalidated before
                    $lifetime -=2;
                }

                if ($lifetime < 0) { //lifetime can't be negative
                    $lifetime = 0;
                }

                $this->cache->save($key, serialize($data), $lifetime);
            } else {
                $data = unserialize($data);
            }

        } else {
            $data = $this->getTokenDatas($config);
        }

        return new AccessToken($data['access_token'], $data['token_type'], $data);
    }

    /**
     * @param $config
     *
     * @return mixed
     */
    protected function getTokenDatas($config)
    {
        $body = $config;
        $body['grant_type'] = $this->grantType;
        unset($body['token_url'], $body['auth_location']);

        $requestOptions = [];

        if ($config['auth_location'] !== 'body') {
            $requestOptions['auth'] = [$config['client_id'], $config['client_secret']];
            unset($body['client_id'], $body['client_secret']);
        }

        $requestOptions['body'] = $body;

        if ($additionalOptions = $this->getAdditionalOptions()) {
            $requestOptions = array_merge_recursive($requestOptions, $additionalOptions);
        }

        $response = $this->client->post($config['token_url'], $requestOptions);

        return $response->json();
    }

    /**
     * compute the current token cache key
     *
     * @param $config
     *
     * @return string
     */
    protected function getCacheKey($config)
    {

        $token_ident = sha1($this->client->getBaseUrl() . '_' . $config['client_id']);

        $key = sprintf(
            'cg_actk_%s_%s',
            $this->grantType,
            $token_ident
        );

        return $key;
    }
}
