import json
import os

def process_cpe(node):
    if node["operator"] == "AND":
        cpe = 

# 读取JSON文件
for file in os.listdir('../nvdcvejson'):
    if file.endswith('.json'):
        with open('nvdcvejson/' + file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # 处理每个"cve"项
            for item in data['CVE_Items']:
                # 保留指定属性
                cpe = process_cpe(item["configurations"]["nodes"][0])
                item['cve'] = {
                    'CVE_data_meta': item['cve']['CVE_data_meta'],
                    'reference_data': item['cve']['references']['reference_data']
                }
                del item['configurations']
                del item['impact']
                del item['publishedDate']
                del item['lastModifiedDate']
        # 写入新的JSON文件
        with open(file, 'w') as f:
            json.dump(data, f, indent=4)



'''
$.each(cveData, function (confIdx, config) {

		displayedCpesCount = 0;
		displayConfiguration(config, confIdx);
		if (isVulnDetailMaxCpeLimitReached(config.totalCpeCount)) {
			vulnCpeTreeHtml += getMaxCPECriteriaShownContent(config.totalCpeCount, confIdx, cveIdVal);
		}
	});

//Display Configuration Id, Toggle link
function displayConfiguration(config, confIdx) {

	vulnCpeTreeHtml += ' <strong data-testid="' + config.dataTestId + '">Configuration ' + config.id + '</strong> ';
	vulnCpeTreeHtml += '(<small><a href="#toggleConfig'
		+ config.id
		+ '" style="text-decoration: underline" id="toggle-configuration-'
		+ config.id
		+ '" data-toggle-config="config-div-'
		+ config.id + '"> hide </a ></small >)<br/>';
	// Iterate Containers
	$.each(config.containers, function (contIdx, container) {
		vulnCpeTreeHtml += '<div id ="config-div-' + config.id
			+ '" > ';
		if (container.configType == BASIC) {
			DisplayBasicConfiguration(container,
				container.configType, config.id);
		} else if (container.configType == RUNNING_ON) {
			DisplayRunningOnConfiguration(container,
				container.configType, config.id);
		} else {
			traverseContainer(container, ADVANCED,
				config.id);
		}
		vulnCpeTreeHtml += '</div>'
	});
	vulnCpeTreeHtml += '<br/>'
}

function getMaxCPECriteriaShownContent(totalCpeCount, configIdx, cveIdVal) {
	return '<span data-testid="vuln-configurations-showing-cpes-container-' + configIdx + '">'
		+ 'Showing ' + MAX_CONFIGCPE + ' of ' + totalCpeCount + ' CPE Match Criteria, <a href="' + serviceBasePath + '/' + cveIdVal + '/cpes">view all CPEs here</a> </span>';
}
'''
