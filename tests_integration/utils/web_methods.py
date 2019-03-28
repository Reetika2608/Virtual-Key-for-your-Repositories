import logging
import time

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import Select

from tests_integration.utils.cdb_methods import get_entitled_list_from_expressway, get_cluster_id_from_expressway
from tests_integration.utils.common_methods import wait_until
from tests_integration.utils.predicates import is_connector_uninstalled
from tests_integration.utils.ssh_methods import run_ssh_command

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def deregister_expressway(exp_hostname, admin_user, admin_pass, org_admin_user, org_admin_pass):
    LOG.info("Deregister Expressway")
    web_driver = create_web_driver()
    cluster_id = get_cluster_id_from_expressway(exp_hostname, admin_user, admin_pass)
    entitled_list = get_entitled_list_from_expressway(exp_hostname, admin_user, admin_pass)
    web_driver.get('https://int-admin.webex.com')
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(3)
    web_driver.get('https://int-admin.webex.com/services/cluster/expressway/' + cluster_id + '/settings')
    while True:
        try:
            web_driver.find_element_by_css_selector(
                'button[ng-click="$ctrl.deactivateService(service, $ctrl.cluster);"]').click()
            web_driver.find_element_by_css_selector('button[ng-click="vm.deactivateService()"]').click()
            time.sleep(3)
        except NoSuchElementException:
            break
    web_driver.find_element_by_css_selector('button[ng-click="$ctrl.deregisterCluster()"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="clusterDeregister.deregister()"]').click()
    print('Wait 10 seconds for deregister to be acknowledged')
    time.sleep(10)

    for connector in [d['name'] for d in entitled_list]:
        wait_until(is_connector_uninstalled, 180, 10, *(exp_hostname,
                                                        admin_user,
                                                        admin_pass,
                                                        connector))

    wait_until(is_connector_uninstalled, 180, 10, *(exp_hostname,
                                                    admin_user,
                                                    admin_pass,
                                                    'd_openj'))

    run_ssh_command(exp_hostname,
                    admin_user,
                    admin_pass,
                    'restart')


def register_expressway(exp_hostname, admin_user, admin_pass, org_admin_user, org_admin_pass):
    LOG.info("Register Expressway")
    web_driver = create_web_driver()
    web_driver.get('https://int-admin.webex.com')
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(3)
    web_driver.find_element_by_link_text('Services').click()
    web_driver.find_element_by_link_text('View').click()
    web_driver.find_element_by_css_selector('button[ng-click="$ctrl.addResource()"]').click()
    web_driver.find_element_by_id('selectedType_expressway').send_keys(' ')
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_name('calendar').send_keys(' ')
    web_driver.find_element_by_name('call').send_keys(' ')
    web_driver.find_element_by_id('service_imp').send_keys(' ')
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_name('hostname').send_keys(exp_hostname)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_name('name').send_keys(exp_hostname)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)
    web_driver.switch_to.window(web_driver.window_handles[1])
    web_driver.find_element_by_name('username').send_keys(admin_user)
    web_driver.find_element_by_name('password').send_keys(admin_pass)
    web_driver.find_element_by_name('formbutton').click()
    web_driver.find_element_by_name('formbutton').click()
    web_driver.find_element_by_id('checkbox1').send_keys(' ')
    web_driver.find_element_by_css_selector('button[ng-click="vm.confirm()"]').click()
    wait_until(is_in_page_source, 120, 5, *(web_driver, " is registered with the Cisco Webex Cloud"))
    web_driver.quit()


def create_web_driver():
    options = webdriver.ChromeOptions()
    options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    options.add_argument("headless")
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--window-size=1920x1080")
    capabilities = DesiredCapabilities.CHROME.copy()
    capabilities["acceptSslCerts"] = True
    capabilities["acceptInsecureCerts"] = True
    capabilities["chrome.switches"] = ["--ignore-certificate-errors"]
    web_driver = webdriver.Chrome("./chromedriver",
                                  options=options,
                                  desired_capabilities=capabilities)
    web_driver.implicitly_wait(10)
    return web_driver


def is_in_page_source(web_driver, text):
    if text in web_driver.page_source:
        return True
    else:
        return False


def is_visible(web_driver, element):
    try:
        web_driver.find_element_by_xpath(element)
        return True
    except:
        return False


def login_expressway(web_driver, exp_hostname, admin_user, admin_pass):
    if not web_driver:
        web_driver = create_web_driver()

    web_driver.get('https://' + exp_hostname)
    web_driver.find_element_by_name('username').send_keys(admin_user)
    web_driver.find_element_by_name('password').send_keys(admin_pass)
    web_driver.find_element_by_name('formbutton').click()


def navigate_expressway_menus(web_driver, menus):
    if not web_driver:
        web_driver = create_web_driver()

    for menu in menus:
        ActionChains(web_driver).move_to_element(web_driver.find_element_by_partial_link_text(menu)).perform()

    ActionChains(web_driver).click().perform()


def enable_expressway_connector(web_driver, exp_hostname, admin_user, admin_pass, connector):
    if not web_driver:
        web_driver = create_web_driver()

    login_expressway(web_driver, exp_hostname, admin_user, admin_pass)
    navigate_expressway_menus(web_driver, ["Applications", "Hybrid Services", "Connector Management"])
    web_driver.find_element_by_partial_link_text("%s" % connector).click()
    select = Select(web_driver.find_element_by_id('enable_service'))
    select.select_by_visible_text('Enabled')
    web_driver.find_element_by_id('save_button').click()
    return "<b>Success</b>: Saved" in web_driver.page_source
