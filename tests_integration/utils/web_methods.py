import datetime
import os
import platform
import time
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException, WebDriverException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support.abstract_event_listener import AbstractEventListener
from selenium.webdriver.support.event_firing_webdriver import EventFiringWebDriver
from selenium.webdriver.support.ui import Select

from tests_integration.utils.common_methods import wait_until_true
from tests_integration.utils.integration_test_logger import get_logger

LOG = get_logger()


class WaitTimeoutException(Exception):
    pass


def deregister_expressway(control_hub, org_admin_user, org_admin_pass, cluster_id, web_driver=None):
    """ Deregister Expressway cluster from control hub through the UI """
    LOG.info("Deregistering Expressway cluster %s from control hub, %s.", cluster_id, control_hub)
    close_web_driver = False
    if web_driver is None:
        close_web_driver = True
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
            time.sleep(3)
            web_driver.find_element_by_css_selector('button[ng-click="vm.deactivateService()"]').click()
            time.sleep(3)
        except NoSuchElementException:
            LOG.info("All services have been deactivated. Proceeding to deregister the cluster.")
            break
    web_driver.find_element_by_css_selector('button[ng-click="$ctrl.deregisterCluster()"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="clusterDeregister.deregister()"]').click()
    LOG.info('Wait 10 seconds for deregister to be acknowledged')
    time.sleep(10)
    if close_web_driver:
        web_driver.quit()


def deactivate_service(control_hub, org_admin_user, org_admin_pass, cluster_id, web_driver=None):
    """ Deactivate a service for a cluster in control hub. Note: this deactivates the first service it encounters. """
    LOG.info("Deactivating a service from the Expressway cluster %s on control hub, %s.", cluster_id, control_hub)
    close_web_driver = False
    if web_driver is None:
        close_web_driver = True
        web_driver = create_web_driver()

    LOG.info("Logging in to control hub, %s, and deactivating the first encountered service for the cluster %s.",
             control_hub, cluster_id)
    web_driver.get('https://' + control_hub)
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(10)
    web_driver.get('https://' + control_hub + '/services/cluster/expressway/' + cluster_id + '/settings')
    time.sleep(10)
    web_driver.find_element_by_css_selector(
        'button[ng-click="$ctrl.deactivateService(service, $ctrl.cluster);"]').click()
    time.sleep(3)
    web_driver.find_element_by_css_selector('button[ng-click="vm.deactivateService()"]').click()
    time.sleep(3)
    if close_web_driver:
        web_driver.quit()


def bootstrap_expressway(control_hub, org_admin_user, org_admin_pass, exp_hostname, web_driver):
    """
    Create a cluster, enable all services, pass bootstrap data to Expressway

    Note that this function requires the caller to either:
     a) provide a web_driver that is already logged in to the Expressway
     or
     b) log in to the 2nd window left open in the web driver after this function returns
    """
    LOG.info("Logging in to control hub, %s, adding the Expressway, %s and activating all services.",
             control_hub, exp_hostname)
    web_driver.get('https://' + control_hub)
    time.sleep(10)
    web_driver.find_element_by_name('email').send_keys(org_admin_user)
    web_driver.find_element_by_xpath('//button').click()
    web_driver.find_element_by_name('IDToken2').send_keys(org_admin_pass)
    web_driver.find_element_by_xpath('//button').click()
    time.sleep(10)
    web_driver.get('https://' + control_hub + '/hybrid-services/clusters')
    time.sleep(10)
    web_driver.find_element_by_css_selector('button[class="md-button md-button--32 md-button--blue"]').click()
    web_driver.find_element_by_xpath('//label[@class="md-radio__label" and @for="selectedType_expressway"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)
    web_driver.find_element_by_xpath('//label[@class="md-checkbox__label" and @for="service_calendar"]').click()
    web_driver.find_element_by_xpath('//label[@class="md-checkbox__label" and @for="service_call"]').click()
    web_driver.find_element_by_xpath('//label[@class="md-checkbox__label" and @for="service_imp"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_name('hostname').send_keys(exp_hostname)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_name('name').send_keys(exp_hostname)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    web_driver.find_element_by_css_selector('button[ng-click="vm.next()"]').click()
    time.sleep(3)


def register_expressway(control_hub, org_admin_user, org_admin_pass, exp_hostname, admin_user, admin_pass, web_driver=None):
    """ Register Expressway through UI """
    LOG.info("Registering Expressway %s", exp_hostname)
    close_web_driver = False
    if web_driver is None:
        close_web_driver = True
        web_driver = create_web_driver()

    try:
        bootstrap_expressway(control_hub, org_admin_user, org_admin_pass, exp_hostname, web_driver)

        LOG.info("Logging in to the Expressway, %s, and completing the registration.", exp_hostname)
        web_driver.switch_to.window(web_driver.window_handles[1])
        web_driver.find_element_by_name('username').send_keys(admin_user)
        web_driver.find_element_by_name('password').send_keys(admin_pass)
        web_driver.find_element_by_name('formbutton').click()
        web_driver.find_element_by_name('formbutton').click()
        web_driver.find_element_by_id('checkbox1').send_keys(' ')
        time.sleep(5)
        web_driver.find_element_by_xpath(
            '/html/body/app-root/div/app-fuse-redirect/div/div/div/div[2]/form/div[2]/button').click()
        if not wait_until_true(is_in_page_source, 120, 5, *(web_driver, " is registered with the Cisco Webex Cloud")):
            raise WaitTimeoutException("Timed out waiting for registration confirmation message")
    finally:
        if close_web_driver:
            web_driver.quit()


def create_web_driver(driver_class=webdriver.Chrome):
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
    web_driver = driver_class(chromedriver_path,
                              options=options,
                              desired_capabilities=capabilities)
    web_driver.implicitly_wait(10)
    return web_driver


def create_screenshotting_web_driver(log_dir, driver=None):
    """ Create a web driver that saves a screenshot to log_dir when an exception is raised """
    if driver is None:
        driver = create_web_driver()
    return EventFiringWebDriver(driver, ExceptionScreenshottingListener(log_dir))


def create_screenshotting_retrying_web_driver(log_dir, max_retries, retry_delay_secs=0.1):
    driver = create_web_driver(click_retrying_class_wrapping(webdriver.Chrome, max_retries, retry_delay_secs))
    return create_screenshotting_web_driver(log_dir, driver)


def click_retrying_class_wrapping(base_class, max_retries, retry_delay_secs):
    """
    Create a class object that can be used to instantiate a retry proxy wrapping a web driver of type base_class.

    The retry proxy will retry max_retries times before failing a click operation on an element.
    """

    if not issubclass(base_class, WebDriver):
        raise ValueError("Base class must be a subclass of WebDriver")

    class ClickRetryingWebDriver(base_class):
        def __init__(self, *args, **kwargs):
            super(ClickRetryingWebDriver, self).__init__(*args, **kwargs)

        def find_element(self, *args, **kwargs):
            return self._find_element_with_current_attempt_count(0, *args, **kwargs)

        def _find_element_with_current_attempt_count(self, current_attempt_count, *args, **kwargs):
            element = super(ClickRetryingWebDriver, self).find_element(*args, **kwargs)
            return ClickRetryingWebDriver._ClickRetryingElementProxy(self,
                                                                     element,
                                                                     current_attempt_count,
                                                                     *args,
                                                                     **kwargs)

        class _ClickRetryingElementProxy(object):
            def __init__(self, driver, element, current_attempt_count, *args, **kwargs):
                self._driver = driver
                self._element = element
                self._attempts = current_attempt_count
                self._args = args
                self._kwargs = kwargs

            def click(self):
                try:
                    return self._element.click()
                except WebDriverException as e:
                    self._attempts += 1
                    if self._attempts > max_retries:
                        LOG.error("Out of retries, throwing")
                        raise e
                    else:
                        time.sleep(retry_delay_secs)
                        LOG.info("Retrying click {}/{} on element".format(self._attempts, max_retries, self._element))
                        self._element = self._driver._find_element_with_current_attempt_count(
                            self._attempts,
                            *self._args,
                            **self._kwargs)
                        self.click()

            def __getattr__(self, attr):
                return getattr(self._element, attr)

    return ClickRetryingWebDriver


class ExceptionScreenshottingListener(AbstractEventListener):
    def __init__(self, logs_dir):
        self._logs_dir = logs_dir

    def on_exception(self, exception, driver):
        file_name = self._logs_dir + "/" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        LOG.info("Saving screenshot: %s.png", file_name)
        driver.save_screenshot("{}.png".format(file_name))

        LOG.info("Saving source code: %s.txt", file_name)
        with open("{}.txt".format(file_name), "w") as f:
            f.write(driver.page_source)

        super(ExceptionScreenshottingListener, self).on_exception(exception, driver)


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

    try:
        login_expressway(web_driver, exp_hostname, admin_user, admin_pass)
        web_driver.get("https://" + exp_hostname + "/fusioncerts")
        if not is_in_page_source(web_driver, "The following certificates have been added by Cisco."):
            web_driver.find_element_by_name('formbutton').click()
        web_driver.get("https://" + exp_hostname + "/fusioncerts")
        if not wait_until_true(is_in_page_source, 90, 1, *(web_driver, "The following certificates have been added by Cisco.")):
            raise WaitTimeoutException("Timed out waiting for certificates-managed-by-Cisco message")
    finally:
        if close_web_driver:
            # If we created the web driver we should close it again.
            web_driver.quit()
