import requests
import json
import sys
import subprocess


def main(tf_plan, rsc_ids, tf_key):
    run_base_url = 'https://app.'
    run_url = ''
    with open(tf_plan) as tf_plan_notices:
        for line in tf_plan_notices:
            if run_base_url in line:
                run_id = line.split('[0m', 1)[0]
                run_id = run_id.split('[0m', 1)[0]
                run_id = run_id.rsplit('/', 1)[-1]
                run_url = "https://app.terraform.io/api/v2/runs/" + run_id
                if len(run_id) > 0:
                    break
    headers = {
        'Content-Type': 'application/vnd.api+json',
        'Authorization': f'Bearer {tf_key}'
    }
    response = requests.request("GET", run_url, headers=headers)
    print(response.status_code)
    j_data = json.loads(response.text)
    j_plan = j_data['data']['relationships']['plan']
    plan_id = j_plan['data']['id']

    plan_url = 'https://app.terraform.io/api/v2/plans/' + plan_id + '/json-output'
    response = requests.request("GET", plan_url, headers=headers)
    j_plan_out = json.loads(response.text)

    json_file = open(rsc_ids)
    json_str = json_file.read()
    rsc_id_map = json.loads(json_str)
    for val in j_plan_out['resource_changes']:
        if 'change' in val:
            if 'create' in val['change']['actions']:
                rsc_name = val['name']
                rsc_tp = val['type']
                kc_rsc_name = val['change']['after']['name']
                if kc_rsc_name in rsc_id_map:
                    rsc_id = rsc_id_map[kc_rsc_name]
                    subprocess.run(['terraform', 'import', rsc_tp + '.' + rsc_name, 'bcregistry/' + rsc_id], cwd='../Terraform')


if __name__ == '__main__':
    globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
