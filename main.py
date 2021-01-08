import sys
import logging
from collections import namedtuple
import json


script_name, *args = sys.argv
script_name = script_name.split('/')[-1]


args_dict = {
    'config': {
        'desc': 'path to custom configuration file',
        'usage': f'\t{script_name} --config conf-file.json',
        'action': None},
    'help': {
        'desc': 'show this help',
        'usage': f'\t{script_name} --help',
        'action': None}
}


allowed_args = args_dict.keys()


def show_help(*args):
    print("\nAvailable parameters:\n")
    for arg, props in args_dict.items():
        print(arg, '\t', props['desc'])
        print('Usage:', '\n', props['usage'])


args_dict['help']['action'] = show_help


config = {
    'logfile': None,
    'threshold': 50
}


def read_conf(*args):

    if len(args) != 1:
        args_dict['help']['action']()
        quit()

    try:
        with open(args[0]) as f:
            custom_config = json.load(f)
            config.update(custom_config)
    except:
        print("Error when reading config file")
        quit()


args_dict['config']['action'] = read_conf


logging.basicConfig(datefmt='%Y.%m.%d %H:%M:%S',
                    format='[%(asctime)s] %(levelname).1s %(message)s',
                    filename=config['logfile'])


params = namedtuple("Params", allowed_args)

for arg in allowed_args:
    setattr(params, arg, None)

for idx, arg in enumerate(args):
    if arg.startswith('--'):
        arg = arg[2:]
        if arg in params._fields:
            arg_params = []
            for p in args[idx + 1:]:
                if p.startswith('--'):
                    break
                arg_params.append(p)
            args_dict[arg]['action'](arg_params)
            # setattr(params, arg, args[idx+1])
        else:
            show_help()
            quit()


if __name__ == '__main__':
    ...
