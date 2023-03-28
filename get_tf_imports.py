import requests
import json
import sys


def pull_terraform_plan_json(auth_str, run_url):
    headers = {
        'Content-Type': 'application/vnd.api+json',
        'Authorization': f'Bearer {auth_str}'
    }

    response = requests.request("GET", run_url, headers=headers)

    j_data = json.loads(response.text)
    j_plan = j_data['data']['relationships']['plan']
    plan_id = j_plan['data']['id']

    plan_url = 'https://app.terraform.io/api/v2/plans/' + plan_id + '/json-output'
    response = requests.request("GET", plan_url, headers=headers)
    return json.loads(response.text)


def main(tf_plan_output, rsc_ids, tf_key):
    run_base_url = 'https://app.terraform.io/app/'
    run_id = ''
    with open(tf_plan_output) as tf_plan_notices:
        while not run_id:
            for line in tf_plan_notices:
                if run_base_url in line:
                    run_id = line.split('[0m', 1)[0].rsplit('/', 1)[-1]

    run_url = "https://app.terraform.io/api/v2/runs/" + run_id
    j_plan_out = pull_terraform_plan_json(tf_key, run_url)

    with open('tf_import_list.txt', 'w') as f:
        json_file = open(rsc_ids)
        json_str = json_file.read()
        rsc_id_map = json.loads(json_str)
        for val in j_plan_out['resource_changes']:
            if 'change' in val:
                if 'create' in val['change']['actions']:
                    rsc_name = val['name']
                    rsc_tp = val['type']
                    if rsc_name in rsc_id_map:
                        rsc_id = rsc_id_map[rsc_name]
                        f.write(rsc_tp + '.' + rsc_name + ' ' + rsc_id + '\n')


if __name__ == '__main__':
    globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
