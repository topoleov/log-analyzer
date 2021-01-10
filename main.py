from pathlib import Path
import sys
import os
from datetime import datetime
import logging
from collections import namedtuple, defaultdict
import json
import gzip
import re
from copy import copy
from string import Template

import argparse


DEFAULT_CONFIG = {
    'logfile': None,
    'threshold': 50,
    'log_dir': '/var/log/nginx/',
    'report_dir': 'reports',
    'log_names_date_format': '%Y%m%d',
    'log_filename': None,
    'log_names_prefix': 'access.log-',
    'log_names_regexp': r"^nginx-access-ui\.log-(\d{8})\.(gz|log)$",
    'log_format':
        r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - -'
        r' \[(?P<dateandtime>\d{2}\/[a-zA-Z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\]'
        r' ((\"(?P<method>GET|POST|PATCH|OPTIONS) )(?P<url>.+)((HTTP|http)\/[0-9]\.[0-9]")) (?P<statuscode>\d{3})'
        r' (?P<bytessent>\d+) (["](?P<referer>(\-)|(\S+))["]) (["](?P<useragent>.+)["])'
        r' (?P<request_time>([0-9]*[.])?[0-9]+) - (["](?P<host>(\-)|(.+))["])',
    'report_template': 'report.html',
}

script_name, *args = sys.argv
script_name = script_name.split('/')[-1]


args_dict = {
    'config': {
        'desc': 'path to custom configuration file',
        'usage': f'\t{script_name} --config [config.json]',
        'action': None},
    'help': {
        'desc': 'show this help',
        'usage': f'\t{script_name} --help',
        'action': None}
}


def show_help(*args):
    print("\nAvailable parameters:\n")
    for arg, props in args_dict.items():
        print(arg, '\t', props['desc'])
        print('Usage:', '\n', props['usage'])


args_dict['help']['action'] = show_help


def read_conf(*args):
    cargs = len(args)
    if cargs > 1:
        args_dict['help']['action']()
        quit()
    if cargs == 1:
        conf_file = 'config.json'
    else:
        conf_file = args[0][0]
    try:
        with open(conf_file) as f:
            custom_config = json.load(f)
    except Exception as e:
        print("Error when reading config file")
        print(e)
        quit()
    return custom_config


args_dict['config']['action'] = read_conf


def get_latest_log(config):

    Log = namedtuple('Log', 'dt ext path')

    if config['target_log_filename'] is not None:
        fn = config['target_log_filename']
        ext = fn.split(".").pop()
        log_path = os.path.join(config['log_dir'], fn)
        latest_log = Log(None, ext, log_path)

    else:
        beard_date = datetime.strptime("19700101", '%Y%m%d')
        latest_log = Log(beard_date, None, None)

        _, _, filenames = next(os.walk(config['log_dir']))

        filenames_pattern = re.compile(config['log_names_regexp'])

        for fn in filenames:
            if fn.startswith(config['log_names_prefix']) or filenames_pattern.match(fn):
                try:
                    *_, dt_part, ext = fn.split('.')
                    log_date_str = dt_part.split('-').pop()
                    log_dt = datetime.strptime(log_date_str, config['log_names_date_format'])
                except ValueError:
                    continue

                if ext not in ('log', 'gz',):
                    continue
                log_path = os.path.join(config['log_dir'], fn)
                log = Log(log_dt, ext, log_path)
                latest_log = log if log.dt > latest_log.dt else latest_log

        if latest_log.dt == beard_date:
            # No log files
            return None

    return latest_log


def parse_log(log):
    log_file = {'gz': gzip.open}.get(log.ext, open)(log.path)

    def log_iterator():
        for line in log_file:
            yield line
        log_file.close()
    return log_iterator


def parse_lines(log_format, lines):

    total_requests = 0
    total_req_time = .0

    url_init = {'count': 0,
                'time_sum': .0,
                'time_avg': .0,
                'time_max': .0,
                'time_med': .0,
                }

    urls = dict()

    try:
        while True:
            line = re.match(log_format, next(lines))
            if not line:
                logging.info("Log file is empty or not match to required `log_format`")
                raise StopIteration
            req_time = float(line.group('request_time'))
            url_ = line.group('url')
            method = line.group('method')
            url_method = method+'::'+url_
            row = urls.get(url_method, copy(url_init))
            row['url'] = url_
            try:
                row['a_host'] = line.group('host')
            except IndexError:
                pass
            row['a_method'] = line.group('method')
            row['count'] += 1
            row['time_sum'] += req_time
            row['time_avg'] = round(row['time_sum'] / row['count'], 3)
            row['time_max'] = req_time if row['time_max'] < req_time else row['time_max']
            urls[url_method] = row

            total_requests += 1
            total_req_time += req_time

    except StopIteration:
        logging.info("Parsing log file finished")
        return total_requests, total_req_time, urls


if __name__ == '__main__':

    for idx, arg in enumerate(args):
        if arg.startswith('--'):
            arg = arg[2:]
            if arg in args_dict.keys():
                arg_params = []
                for p in args[idx + 1:]:
                    if p.startswith('--'):
                        break
                    arg_params.append(p)
                if arg == 'config':
                    custom_config = args_dict[arg]['action'](arg_params)
                    config = copy(DEFAULT_CONFIG)
                    config.update(custom_config)
                    continue
                args_dict[arg]['action'](arg_params)
                # setattr(params, arg, args[idx+1])
            else:
                show_help()
                quit()

        logging.basicConfig(
            level='INFO',
            datefmt='%Y.%m.%d %H:%M:%S',
            format='[%(asctime)s] %(levelname).1s %(message)s',
            filename=config['logfile'])

        logging.info("Starting...")

        latest_log = get_latest_log(config)

        if latest_log is None:
            logging.info(
                f"No log files that match the template \
                `[{config['log_names_prefix']}|{config['log_names_regexp']}]-{config['log_date_format']}.[gz|log]` \
                in `log_dir` ({config['log_dir']})\n--end--")
            quit()

        if latest_log.dt is None:
            report_name_postfix = 'target'+datetime.today().strftime("%Y.%m.%d.%H:%M")
        else:
            report_name_postfix = latest_log.dt.strftime("%Y.%m.%d")

        latest_log_report_name = f'report-{report_name_postfix}.html'
        latest_log_report_path = os.path.join(config['report_dir'], latest_log_report_name)

        # TODO
        # if os.path.exists(latest_log_report_path):
        #     logging.info(f"Report on latest logfile already exist. \n--end--")
        #     quit()

        log_lines = parse_log(latest_log)()

        total_requests, total_req_time, urls = parse_lines(config['log_format'], log_lines)

        for url, stat in urls.items():
            stat['count_perc'] = round(stat['count']/total_requests*100, 2)
            stat['time_perc'] = round(stat['time_sum']/total_req_time*100, 2)

        with open(config['report_template'], 'rb') as f:
            template = Template(f.read().decode('utf-8'))
        report = template.safe_substitute(table_json=json.dumps(list(urls.values())))

        with open(latest_log_report_path, 'wb') as report_file:
            Path(config['report_dir']).mkdir(parents=True, exist_ok=True)
            report_file.write(report.encode('utf-8'))
