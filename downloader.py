import time
from selenium import webdriver
from selenium.common import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
import logging


class Downloader:
    # TODO: Handle anchor ('#') references in URLs (take only the referenced part) - e.g. 'https://wikileaks.org/vault7/#Pandemic'

    @staticmethod
    def fetch_website(url: str) -> str | None:
        logging.info('\t\t\tInitializing Chrome web driver')
        options = Options()
        options.add_argument("--headless=new")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.maximize_window()
        driver.set_page_load_timeout(90)

        try:
            logging.info('\t\t\tFetching website')
            driver.get(url)

            logging.info('\t\t\tScrolling down to the bottom of the page')
            last_height = driver.execute_script("return document.body.scrollHeight")
            while True:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(1)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height

            logging.info('\t\t\tWaiting for page to fully load')
            stability_threshold = 3
            stable_count = 0
            last_page_source = driver.page_source
            while stable_count < stability_threshold:
                time.sleep(1)
                current_page_source = driver.page_source
                if current_page_source == last_page_source:
                    stable_count += 1
                else:
                    stable_count = 0
                last_page_source = current_page_source

            logging.info('\t\t\tExtracting relevant element')
            relevant_element = driver
            bodies = relevant_element.find_elements(By.TAG_NAME, 'body')
            if bodies:
                relevant_element = bodies[0]
            mains = relevant_element.find_elements(By.TAG_NAME, 'main')
            if mains:
                relevant_element = mains[0]
            articles = relevant_element.find_elements(By.TAG_NAME, 'article')
            if articles:
                relevant_element = articles[0]

            # logging.info('\t\t\tFiltering images and fixing source URLs')
            # for image in relevant_element.find_elements(By.TAG_NAME, 'img'):
            #     # Check if image is smaller than 150x150 pixels
            #     if 0 < image.size['height'] <= 150 and 0 < image.size['width'] <= 150:
            #         # Check if parent is a <figure> and remove it, otherwise just remove the img
            #         parent_element = image.find_element(By.XPATH, '..')  # Get parent element
            #         if parent_element.tag_name == 'figure':
            #             relevant_element.execute_script("arguments[0].remove();", parent_element)
            #         else:
            #             relevant_element.execute_script("arguments[0].remove();", image)
            #     else:
            #         src = image.get_attribute('src')
            #         relevant_element.execute_script("arguments[0].setAttribute('src', arguments[1]);", image, src)
            #         # Remove other attributes that might interfere with the image
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-lazyload');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-src');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-lazy-src');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-lazyload-src');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('srcset');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-srcset');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-lazy-srcset');", image)
            #         relevant_element.execute_script("arguments[0].removeAttribute('data-lazyload-srcset');", image)

            html = relevant_element.get_attribute('outerHTML')
        except WebDriverException:
            logging.error('\t\t\tFailed to fetch website')
            return None
        finally:
            driver.quit()

        return html
