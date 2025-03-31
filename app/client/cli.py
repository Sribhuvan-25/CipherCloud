import click
import asyncio
from pathlib import Path
from .client import SecureCloudClient

@click.group()
def cli():
    """Secure Cloud Storage CLI"""
    pass

@cli.command()
@click.option('--user-id', required=True, help='User ID for key generation')
@click.option('--keys-dir', default='keys', help='Directory to store keys')
def init(user_id: str, keys_dir: str):
    """Initialize a new user with key pair"""
    client = SecureCloudClient('http://localhost:8000', user_id)
    keys = client.generate_keypair(Path(keys_dir))
    click.echo(f"Keys generated and saved in {keys_dir}/")

@cli.command()
@click.argument('file-path')
@click.option('--user-id', required=True, help='User ID')
@click.option('--private-key', required=True, help='Path to private key')
@click.option('--token', required=True, help='Authentication token')
def upload(file_path: str, user_id: str, private_key: str, token: str):
    """Upload and encrypt a file"""
    client = SecureCloudClient('http://localhost:8000', user_id)
    client.load_private_key(private_key)
    client.set_token(token)
    
    result = asyncio.run(client.upload_file(file_path))
    click.echo(f"File uploaded successfully. File ID: {result['file_id']}")

@cli.command()
@click.argument('file-id')
@click.argument('output-path')
@click.option('--user-id', required=True, help='User ID')
@click.option('--private-key', required=True, help='Path to private key')
@click.option('--token', required=True, help='Authentication token')
def download(file_id: str, output_path: str, user_id: str, private_key: str, token: str):
    """Download and decrypt a file"""
    client = SecureCloudClient('http://localhost:8000', user_id)
    client.load_private_key(private_key)
    client.set_token(token)
    
    asyncio.run(client.download_file(file_id, output_path))
    click.echo(f"File downloaded and decrypted to {output_path}")

if __name__ == '__main__':
    cli() 