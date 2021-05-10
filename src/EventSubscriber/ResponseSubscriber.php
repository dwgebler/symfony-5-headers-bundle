<?php
namespace Gebler\SecurityHeadersBundle\EventSubscriber;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class ResponseSubscriber implements EventSubscriberInterface
{
    private ParameterBagInterface $parameterBag;

    public function __construct(ParameterBagInterface $parameterBag)
    {
        $this->parameterBag = $parameterBag;
    }
    
    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::RESPONSE => [
                ['addSecurityHeaders', 0],
            ],
        ];
    }

    public function addSecurityHeaders(ResponseEvent $event)
    {
        $frameOptions = $this->parameterBag->get('security_headers.frames');
        $mimeSniffing = $this->parameterBag->get('security_headers.sniff_mimes');
        $https = $this->parameterBag->get('security_headers.https');
        $csp = $this->parameterBag->get('security_headers.content');

        $strictTransport = '';
        $contentSecurityPolicy = "default-src '{$csp['default']}'";

        if ($https['required']) {
            $strictTransport = 'max-age=63072000';
            if ($https['subdomains']) {
                $strictTransport .= '; includeSubDomains';
            }
            if ($https['preload']) {
                $strictTransport .= '; preload';
            }
        }

        if ($csp['upgrade_insecure']) {
            $contentSecurityPolicy .= "; upgrade-insecure-requests";
        }
        if ($csp['styles_inline']) {
            $contentSecurityPolicy .= "; style-src-attr 'unsafe-inline'";
        }

        $contentSecurityPolicy .= "; script-src";
        foreach ($csp['scripts'] as $src) {
            if ($src === "self") {
                $src = "'self'";
            }
            $contentSecurityPolicy .= " ".$src;
        }

        $contentSecurityPolicy .= "; style-src";
        foreach ($csp['styles'] as $src) {
            if ($src === "self") {
                $src = "'self'";
            }
            $contentSecurityPolicy .= " ".$src;
        }


        $response = $event->getResponse();

        if ($mimeSniffing === false) {
            $response->headers->set('X-Content-Type-Options', 'nosniff');
        }
        $response->headers->set('X-Frame-Options`', $frameOptions);
        $response->headers->set('Strict-Transport-Security', $strictTransport);
        $response->headers->set('Content-Security-Policy', $contentSecurityPolicy);
    }
}