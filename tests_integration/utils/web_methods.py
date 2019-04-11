import os
import platform
import time

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import Select

from tests_integration.utils.common_methods import wait_until_true
from tests_integration.utils.integration_test_logger import get_logger

LOG = get_logger()


def deregister_expressway(control_hub, org_admin_user, org_admin_pass, cluster_id):
    """ Deregister Expressway cluster from control hub through the UI """
    LOG.info("Deregistering Expressway cluster %s from control hub, %s.", cluster_id, control_hub)
    web_driver = create_web_driver()

    LOG.info("Logging in to control hub, %s, deactivating all services and deregistering the cluster %s.",
             control_hub, cluster_id)
    web_driver.get('https://' + control_hub)
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(3)
    web_driver.get('https://' + control_hub + '/services/cluster/expressway/' + cluster_id + '/settings')
    time.sleep(2)
    while True:
        try:
            web_driver.find_element_by_css_selector(
                'button[ng-click="$ctrl.deactivateService(service, $ctrl.cluster);"]').click()
            web_driver.find_element_by_css_selector('button[ng-click="vm.deactivateService()"]').click()
            time.sleep(3)
        except NoSuchElementException:
            LOG.info("All services have been deactivated. Proceeding to deregister the cluster.")
            break
    web_driver.find_element_by_css_selector('button[ng-click="$ctrl.deregisterCluster()"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="clusterDeregister.deregister()"]').click()
    LOG.info('Wait 10 seconds for deregister to be acknowledged')
    time.sleep(10)
    web_driver.quit()


def deactivate_service(control_hub, org_admin_user, org_admin_pass, cluster_id):
    """ Deactivate a service for a cluster in control hub. Note: this deactivates the first service it encounters. """
    LOG.info("Deactivating a service from the Expressway cluster %s on control hub, %s.", cluster_id, control_hub)
    web_driver = create_web_driver()

    LOG.info("Logging in to control hub, %s, and deactivating the first encountered service for the cluster %s.",
             control_hub, cluster_id)
    web_driver.get('https://' + control_hub)
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(3)
    web_driver.get('https://' + control_hub + '/services/cluster/expressway/' + cluster_id + '/settings')
    web_driver.find_element_by_css_selector(
        'button[ng-click="$ctrl.deactivateService(service, $ctrl.cluster);"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="vm.deactivateService()"]').click()
    time.sleep(3)
    web_driver.quit()


def register_expressway(control_hub, org_admin_user, org_admin_pass, exp_hostname, admin_user, admin_pass):
    """ Register Expressway through UI """
    LOG.info("Registering Expressway %s", exp_hostname)
    web_driver = create_web_driver()

    LOG.info("Logging in to control hub, %s, adding the Expressway, %s and activating all services.",
             control_hub, exp_hostname)
    web_driver.get('https://' + control_hub)
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(3)
    web_driver.find_element_by_link_text('Services').click()
    time.sleep(2)
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
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)

    LOG.info("Logging in to the Expressway, %s, and completing the registration.", exp_hostname)
    web_driver.switch_to.window(web_driver.window_handles[1])
    web_driver.find_element_by_name('username').send_keys(admin_user)
    web_driver.find_element_by_name('password').send_keys(admin_pass)
    web_driver.find_element_by_name('formbutton').click()
    web_driver.find_element_by_name('formbutton').click()
    web_driver.find_element_by_id('checkbox1').send_keys(' ')
    web_driver.find_element_by_css_selector('button[ng-click="vm.confirm()"]').click()
    wait_until_true(is_in_page_source, 120, 5, *(web_driver, " is registered with the Cisco Webex Cloud"))
    web_driver.quit()


def create_web_driver():
    """ Create a web_driver """
    LOG.info("Creating web driver")
    platform_os = platform.system()
    if platform_os == 'Linux':
        chromebinary_path = '/usr/bin/google-chrome'
        chromedriver_path = './tests_integration/ui_based_tests/chromedriver_linux'
    else:
        chromebinary_path = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        chromedriver_path = './tests_integration/ui_based_tests/chromedriver_mac'

    if not os.path.isfile(chromedriver_path):
        chromedriver_path = './' + chromedriver_path.split("/")[-1]

    options = webdriver.ChromeOptions()
    options.binary_location = chromebinary_path
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--window-size=1920x1080")
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    capabilities = DesiredCapabilities.CHROME.copy()
    capabilities["acceptSslCerts"] = True
    capabilities["acceptInsecureCerts"] = True
    capabilities["chrome.switches"] = ["--ignore-certificate-errors"]
    web_driver = webdriver.Chrome(chromedriver_path,
                                  options=options,
                                  desired_capabilities=capabilities)
    web_driver.implicitly_wait(10)
    return web_driver


def is_in_page_source(web_driver, text):
    """ Is the text in the page source of the current web_driver page """
    if text in web_driver.page_source:
        return True

    return False


def is_visible(web_driver, element):
    """ Is element visible to the web_driver? """
    try:
        web_driver.find_element_by_xpath(element)
        return True
    except:
        return False


def login_expressway(web_driver, exp_hostname, admin_user, admin_pass):
    """ Log in an Expressway through the browser """
    LOG.info("Logging in to Expressway %s through the UI.", exp_hostname)

    close_web_driver = False
    if not web_driver:
        close_web_driver = True
        web_driver = create_web_driver()

    web_driver.get('https://' + exp_hostname)
    web_driver.find_element_by_name('username').send_keys(admin_user)
    web_driver.find_element_by_name('password').send_keys(admin_pass)
    web_driver.find_element_by_name('formbutton').click()

    if close_web_driver:
        # If we created the web driver we should close it again.
        web_driver.quit()


def navigate_expressway_menus(web_driver, menus):
    """ Navigate the menus of the Expressway through the browser. The Expressway must be logged in. """
    LOG.info("Navigate through the menus %s", menus)
    close_web_driver = False
    if not web_driver:
        close_web_driver = True
        web_driver = create_web_driver()

    for menu in menus:
        ActionChains(web_driver).move_to_element(web_driver.find_element_by_partial_link_text(menu)).perform()

    ActionChains(web_driver).click().perform()

    if close_web_driver:
        # If we created the web driver we should close it again.
        web_driver.quit()


def enable_expressway_connector(web_driver, exp_hostname, admin_user, admin_pass, connector):
    """ Enable a connector on Expreswway through the UI """
    LOG.info("Logging in to Expressway %s and enabling connector %s.", exp_hostname, connector)
    close_web_driver = False
    if not web_driver:
        close_web_driver = True
        web_driver = create_web_driver()

    login_expressway(web_driver, exp_hostname, admin_user, admin_pass)
    navigate_expressway_menus(web_driver, ["Applications", "Hybrid Services", "Connector Management"])
    try:
        web_driver.find_element_by_partial_link_text("%s" % connector).click()
    except StaleElementReferenceException:
        # The Ajax connector status table changed causing selenium to think that the object it has found is different.
        # Retrying.
        web_driver.find_element_by_partial_link_text("%s" % connector).click()
    select = Select(web_driver.find_element_by_id('enable_service'))
    select.select_by_visible_text('Enabled')
    web_driver.find_element_by_id('save_button').click()
    res = "<b>Success</b>: Saved" in web_driver.page_source

    if close_web_driver:
        # If we created the web driver we should close it again.
        web_driver.quit()

    return res


def enable_expressway_cert_management(exp_hostname, admin_user, admin_pass, web_driver=None):
    """ Enable cert management on Expreswway through the UI """
    LOG.info("Logging in to Expressway %s and enabling managed certs.", exp_hostname)
    close_web_driver = False
    if not web_driver:
        close_web_driver = True
    web_driver = create_web_driver()

    login_expressway(web_driver, exp_hostname, admin_user, admin_pass)
    web_driver.get("https://" + exp_hostname + "/fusioncerts")
    web_driver.find_element_by_name('formbutton').click()
    wait_until_true(is_in_page_source, 30, 1, *(web_driver, "The following certificates have been added by Cisco."))

    if close_web_driver:
        # If we created the web driver we should close it again.
        web_driver.quit()
