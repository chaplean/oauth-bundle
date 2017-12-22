<?php

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

/**
 * Class SlackResourceOwner.
 *
 * @package   Chaplean\Bundle\OAuthBundle\OAuth\ResourceOwner
 * @author    Tom - Chaplean <tom@chaplean.com>
 * @copyright 2014 - 2015 Chaplean (http://www.chaplean.com)
 * @since     0.1.0
 */
class SlackResourceOwner extends GenericOAuth2ResourceOwner
{
    protected $paths = [
        'identifier' => 'id',
        'nickname'   => 'name',
        'realname'   => 'profile.real_name',
        'email'      => 'profile.email',
    ];

    /**
     * Configure options.
     *
     * @param OptionsResolver $resolver Resolver.
     *
     * @return void
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(
            [
                'authorization_url'        => 'https://slack.com/oauth/authorize',
                'access_token_url'         => 'https://slack.com/api/oauth.access',
                'infos_url'                => 'https://slack.com/api/auth.test',
                'user_url'                 => 'https://slack.com/api/users.info',
                'scope'                    => 'identify,read,post',
                'use_commas_in_scope'      => true,
                'use_bearer_authorization' => false
            ]
        );

        $resolver->setDefined(['team']);
    }

    /**
     * Get Authorization Url
     *
     * @param string $redirectUri     Redirect URI
     * @param array  $extraParameters Extra parameters
     *
     * @return string
     */
    public function getAuthorizationUrl($redirectUri, array $extraParameters = [])
    {
        if ($this->options['csrf']) {
            if (null === $this->state) {
                $this->state = $this->generateNonce();
            }

            $this->storage->save($this, $this->state, 'csrf_state');
        }

        $parameters = array_merge(
            [
                'response_type' => 'code',
                'client_id'     => $this->options['client_id'],
                'scope'         => str_replace(' ', ',', $this->options['scope']),
                'state'         => $this->state ? urlencode($this->state) : null,
                'redirect_uri'  => $redirectUri,
                'team'          => (isset($this->options['team']) ? $this->options['team'] : '')
            ],
            $extraParameters
        );

        return $this->normalizeUrl($this->options['authorization_url'], $parameters);
    }

    /**
     * Get User Information
     *
     * @param array $accessToken     Access token
     * @param array $extraParameters Extra parameters
     *
     * @return mixed
     */
    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        if ($this->options['use_bearer_authorization']) {
            $url = $this->normalizeUrl($this->options['infos_url']);
            $response = $this->httpRequest($url, null, ['Authorization: Bearer ' . $accessToken['access_token']]);
        } else {
            $url = $this->normalizeUrl($this->options['infos_url'], ['token' => $accessToken['access_token']]);
            $response = $this->doGetUserInformationRequest($url);
        }

        $infosContent = $response->getBody();

        $user = null;

        if ($infosContent != '') {
            $infosJson = json_decode($infosContent, true);

            $url = $this->normalizeUrl(
                $this->options['user_url'],
                [
                    'token' => $accessToken['access_token'],
                    'user'  => $infosJson['user_id']
                ]
            );
            $userResponse = $this->httpRequest($url);

            $userContent = $userResponse->getBody();

            if ($userContent != '') {
                $userJson = json_decode($userContent, true);

                if (isset($userJson['user'])) {
                    $user = array_merge($infosJson, $userJson['user']);
                    $user['token'] = $accessToken['access_token'];
                }
            }
        }

        if ($user === null) {
            throw new AuthenticationException("User data could not be loaded");
        }

        $response = $this->getUserResponse();
        $response->setData($user);
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }
}
