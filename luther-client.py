#  _         _    _
# | |       | |  | |
# | | _   _ | |_ | |__    ___  _ __
# | || | | || __|| '_ \  / _ \| '__|
# | || |_| || |_ | | | ||  __/| |
# |_| \__,_| \__||_| |_| \___||_|
#

import click
import requests
import json
from tabulate import tabulate

DEFAULT_PROVIDER = 'https://dnsd.co'
DEFAULT_API_VERSION = 'v1'


class Luther(object):
    def __init__(self, provider=None, verbose=False,
                 credentials=None, blind=False):
        self.provider = provider
        self.verbose = verbose
        self.credentials = credentials
        self.blind = blind
        self.request_result = None
        self.json = None

    def send_request(self, type, dest, auth=False, data=None):
        auth = self.credentials if auth else None
        if self.verbose:
            extra = ''
            if auth:
                extra += ', Auth: ON'
            if data:
                extra += ', JSON'
            click.secho(
                type.upper()+' '+self.provider+'/api/v1/'+dest+extra,
                fg='yellow')
        headers = {'content-type': 'application/json'} if json else None
        self.request_result = requests.__dict__[type](
            self.provider+'/api/v1/'+dest,
            auth=auth,
            data=json.dumps(data),
            headers=headers
        )
        self.check_result()

    def check_result(self):
        if self.request_result.status_code >= 300:
            click.secho('BAD!', fg='red', bold=True)
            click.secho('Status Code: '+str(self.request_result.status_code))
            if self.request_result.json():
                message = self.request_result.json().get('message') or \
                    self.request_result.json().get('error')
                click.echo('Message: '+message)
            raise click.Abort()
        if self.verbose:
            click.secho(
                'Status Code: '+str(self.request_result.status_code),
                fg='yellow'
            )
        if self.request_result.json():
            self.json = self.request_result.json()
        if self.verbose:
            click.secho('OK!', fg='green', bold=True)


pass_setup = click.make_pass_decorator(Luther)


def validate_credentials(ctx, param, value):
    try:
        user, password = map(str, value.split(':', 2))
        return (user, password)
    except ValueError:
        raise click.BadParameter(
            'credentials should be in the format user:password'
        )


@click.group()
@click.option(
    '--credentials',
    '-c',
    default=None,
    type=str,
    callback=validate_credentials,
    help=('Provide credentials that are required by certain '
          'commands (credentials should be in the format user:pass)')
)
@click.option(
    '--provider',
    '-p',
    envvar='LUTHER_PROVIDER',
    default=DEFAULT_PROVIDER,
    help=('Use a specific luther provider instead of '
          'the default (http://dnsd.co)')
)
@click.option(
    '--blind-yes',
    '-y',
    default=False,
    is_flag=True,
    help='Don\'t ask any questions'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    default=False
)
@click.pass_context
def cli(ctx, provider, verbose, credentials, blind_yes):
    """
    a command line tool for interacting with a luther rest api.
    """
    if credentials:
        credentials = requests.auth.HTTPBasicAuth(
            credentials[0],
            credentials[1]
        )
    if provider and provider[-1] == '/':
        provider = provider[:-1]
    ctx.obj = Luther(
        provider=provider,
        verbose=verbose,
        credentials=credentials,
        blind=blind_yes
    )

##################
# Random actions #
##################


@cli.command('guess_ip')
@pass_setup
def guess_ip(luther):
    """Get your IP"""
    luther.send_request('get', 'guess_ip')
    click.secho(luther.json['guessed_ip'])

################
# User actions #
################


@cli.command('sign_up')
@click.argument('email')
@click.password_option()
@pass_setup
def sign_up(luther, email, password):
    """Sign up for luther"""
    user = {
        'email': email,
        'password': password
    }
    luther.send_request('post', 'user', data=user)
    click.secho(luther.json['message'])


@cli.command('change_password')
@click.password_option()
@pass_setup
def change_password(luther, password):
    """Change your luther password"""
    change = {
        'new_password': password
    }
    luther.send_request('put', 'user', data=change, auth=True)
    click.secho(luther.json['message'])


@cli.command('delete_account')
@pass_setup
def delete_account(luther):
    """Delete your luther account"""

    delete = {
        'confirm': 'DELETE'
    }
    luther.send_request('delete', 'user', data=delete, auth=True)
    click.secho(luther.json['message'])

#####################
# Subdomain actions #
#####################


@cli.command('my_subdomains')
@pass_setup
def my_subdomains(luther):
    """Print your subdomains"""
    luther.send_request('get', 'subdomains', auth=True)
    if luther.json.get('subdomains'):
        results = [[
            s['subdomain'],
            s['full_domain'],
            s['ip'],
            s['subdomain_token'],
            s['last_updated']
        ] for s in luther.json['subdomains']]
        click.secho(
            tabulate(
                results,
                [
                    'subdomain',
                    'full domain',
                    'ip',
                    'subdomain_token',
                    'last update'
                ]
            )
        )
    else:
        click.secho(luther.json['message'])


@cli.command('new_subdomain')
@click.argument('subdomain')
@click.option('--ip', type=str, default=None, help='IP to point subdomain to')
@pass_setup
def new_subdomain(luther, subdomain, ip):
    """Create a new subdomain"""
    new_sub = {'subdomain': subdomain}
    if ip:
        new_sub['ip'] = ip
    luther.send_request('post', 'subdomains', data=new_sub, auth=True)
    click.secho('Subdomain added\n')
    click.secho(
        tabulate(
            [[
                luther.json['subdomain'],
                luther.json['full_domain'],
                luther.json['ip'],
                luther.json['subdomain_token']
            ]],
            ['subdomain', 'full domain', 'ip', 'subdomain_token']
        )
    )


@cli.command('update_subdomain')
@click.argument('subdomain')
@click.argument('subdomain_token')
@click.option('--ip', type=str, default=None, help='IP to point subdomain to')
@pass_setup
def update_subdomain(luther, subdomain, subdomain_token, ip):
    """Update a subdomain"""
    update_sub = '/'.join(['subdomains', subdomain, subdomain_token])
    if ip:
        update_sub += '/'+ip
    luther.send_request('get', update_sub)
    if luther.json.get('message'):
        click.secho(luther.json['message'])
    click.secho(
        tabulate(
            [[
                luther.json['subdomain'],
                luther.json['full_domain'],
                luther.json['ip'],
                luther.json['subdomain_token']
            ]],
            ['subdomain', 'full domain', 'ip', 'subdomain_token']
        )
    )


@cli.command('delete_subdomain')
@click.argument('subdomain')
@pass_setup
def delete_subdomain(luther, subdomain):
    """Delete a subdomain"""
    delete_sub = {
        'subdomain': subdomain,
        'confirm': 'DELETE'
    }
    luther.send_request('delete', 'subdomains', data=delete_sub, auth=True)
    click.secho(luther.json['message'])


if __name__ == '__main__':
    cli()
