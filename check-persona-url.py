#!/usr/bin/env python
import json
import os
import requests

# https://bugzilla.mozilla.org/show_bug.cgi?id=781838
# - POSTs MUST never redirect
# - POST over non-SSL MUST fail 400 Bad Non-SSL
# - GETs to the old domains MUST redirect to the new domain
# - www. MUST always redirect
# - requests to static MUST NOT redirect
# - requests to verifier - don't allow GET? Only allow POST /verify?

verify_args = { 'assertion': 'foo', 'audience': 'bar' }

# checker functions
def post_http(response):
  if response.json.get('error') != 'Please use HTTPS rather than HTTP':
    print ("  ERROR: wrong response: got: %s, expected '%s'" %
           (response.text, '{"error": "Please use HTTPS rather than HTTP"}'))


def dummy_verify(response):
  try:
    if response.json['status'] != 'failure':
      print ("  ERROR: wrong response: got: %s, expected '%s'" %
             (response.json['status'], 'failure'))
    if response.json['reason'] != 'no certificates provided':
      print ("  ERROR: wrong response: got: %s, expected '%s'" %
             (response.json['status'], 'no certificates provided'))
  except:
    print ("  ERROR: wrong response: got non conforming json response: %s" %
             (response.text))

def disallowed_verify(response):
  try:
    if response.json['status'] != 'failure':
      print ("  ERROR: wrong response: got: %s, expected '%s'" %
             (response.json['status'], 'failure'))
  except:
    print ("  ERROR: wrong response: got non conforming json response: %s" %
             (response.text))

# s/anosrep.org/persona.org/; s/diresworb.org/browserid.org/
def rewrite_checks(checks):
  if not os.environ.get('CHECK_PERSONA_ORG'):
    return checks
  for check in checks:
    check['url'] = check['url']\
        .replace('anosrep.org', 'persona.org')\
        .replace('diresworb.org', 'browserid.org')
    if 'redir' in check:
      check['redir'] = check['redir']\
          .replace('anosrep.org', 'persona.org')\
          .replace('diresworb.org', 'browserid.org')
  return checks


checks = rewrite_checks(
  [
    # GET main site over HTTP by its various hostnames.
    { 'meth': 'GET', 'rc': 301, 'url': 'http://diresworb.org/',              'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://diresworb.org/about',         'redir': 'https://login.anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://www.diresworb.org/',          'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://www.diresworb.org/about',     'redir': 'https://login.anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://anosrep.org/',                'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 404, 'url': 'http://anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://www.anosrep.org/',            'redir': 'https://anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://www.anosrep.org/about',       'redir': 'https://anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://verifier.login.anosrep.org/', 'redir': 'https://verifier.login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://static.login.anosrep.org/',   'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 200, 'url': 'http://static.login.anosrep.org/v/fb5534092a/production/browserid.css' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://login.anosrep.org/',          'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'http://login.anosrep.org/about',     'redir': 'https://login.anosrep.org/about' },

    # GET main site over HTTPS by its various hostnames. XXX currently in stage
    # the first 4 return 302. Minor difference and we can change this check to
    # expect 302.
    { 'meth': 'GET', 'rc': 301, 'url': 'https://diresworb.org/',             'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://diresworb.org/about',        'redir': 'https://login.anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://www.diresworb.org/',         'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://www.diresworb.org/about',    'redir': 'https://login.anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://anosrep.org/',               'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 404, 'url': 'https://anosrep.org/about' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://www.anosrep.org/',           'redir': 'https://anosrep.org/' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://www.anosrep.org/about',      'redir': 'https://anosrep.org/about' },
    { 'meth': 'GET', 'rc': 405, 'url': 'https://verifier.login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 404, 'url': 'https://login.anosrep.org/verify' },
    { 'meth': 'GET', 'rc': 301, 'url': 'https://static.login.anosrep.org/',  'redir': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 200, 'url': 'https://static.login.anosrep.org/v/fb5534092a/production/browserid.css' },
    { 'meth': 'GET', 'rc': 200, 'url': 'https://login.anosrep.org/' },
    { 'meth': 'GET', 'rc': 200, 'url': 'https://login.anosrep.org/about' },

    # POST to /verify over HTTP => 400 with 'Please use HTTPS rather than HTTP'.
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://diresworb.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://www.diresworb.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://www.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 400, 'check': post_http, 'postargs': verify_args, 'url': 'http://verifier.login.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://static.login.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': post_http, 'postargs': verify_args, 'url': 'http://login.anosrep.org/verify' },

    # POST to /verify over HTTPS. Odd test here in which I pass in arguments
    # that will return 200 with a specific message that tells me that I
    # successfully reached all the way in to the verify workers.  If I don't
    # get that message then network/routing is wrong.
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://diresworb.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://www.diresworb.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://www.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 200, 'check': dummy_verify, 'postargs': verify_args, 'url': 'https://verifier.login.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 404, 'check': dummy_verify, 'postargs': verify_args, 'url': 'https://verifier.login.anosrep.org/' },
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://static.login.anosrep.org/verify' },
    { 'meth': 'POST', 'rc': 405, 'check': disallowed_verify, 'postargs': verify_args, 'url': 'https://login.anosrep.org/verify' },
])


def check_persona(args):
  if args['meth'] == 'POST':
    data = json.dumps(args.get('postargs')) if args.get('postargs') else ''
    headers = {'content-type': 'application/json'}
    response = requests.post(args['url'], allow_redirects=False,
                             data=data, headers=headers)
  else:
    response = requests.get(args['url'], allow_redirects=False)

  location = ''
  if response.status_code in [301, 302]:
    location = response.headers['location']

  print ('%-4s %-50s %4s %s' %
         (args['meth'], args['url'], response.status_code, location))

  if args.get('redir') and args['redir'] != location:
    print ('  ERROR: Wrong redirection URL: got: %s, expected: %s' %
           (location, args['redir']))
  if response.status_code != args['rc']:
    print ('  ERROR: Wrong response code: got: %d, expected: %d' %
           (response.status_code, args['rc']))
  if args.get('check'):
    args['check'](response)


for check in checks:
  check_persona(check)
