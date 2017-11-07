from . import file_keys

def main(argv):
	protected_path = os.environ.get('PROTECTED_PATH', 'protected.yaml')
	keyfile = file_keys.KeyFile(protected_path)
	## TODO execute one of with_new_domain, with_secret,
	## eith_owner, with_new_key_custodian
	modified = key_file.method(args)
	modified.write()
	## decrypt domain doesn't modify the file
