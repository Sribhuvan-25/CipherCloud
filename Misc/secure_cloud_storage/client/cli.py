import click
from ..utils.benchmarks import run_all_benchmarks
from ..utils.security_tests import perform_security_evaluation

@cli.group()
def benchmark():
    """Run benchmarks and tests"""
    pass

@benchmark.command()
@click.option('--server', default='http://localhost:5000', help='Server URL')
@click.option('--user-id', envvar='SECURE_CLOUD_USER_ID', help='User ID')
@click.option('--private-key', required=True, help='Path to private key file')
def performance(server, user_id, private_key):
    """Run performance benchmarks"""
    results = run_all_benchmarks(server, user_id, private_key)
    click.echo("Benchmark complete!")
    
@benchmark.command()
def security():
    """Run security tests"""
    results = perform_security_evaluation()
    click.echo("Security evaluation complete!") 
    