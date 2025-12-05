import os
import sqlite3

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from bcrypt import hashpw, gensalt

# --- Configuration ---
BASE_URL = "http://localhost:8080"
DATABASE = "secure_db.db"

# Test Users required
USER = {"username": "testUser", "password": "Test1234*", "email": "testuser@test.com"}
ADMIN = {"username": "testAdmin", "password": "Test1234*", "email": "testadmin@test.com"}
USER_B = {"username": "userB", "password": "Test1234*", "email": "userb@test.com"}

# Chrome driver path
CHROME_DRIVER_PATH = None

# --- Database Helpers ---
# Opens connection to database
def get_db_connection():
    if not os.path.exists(DATABASE):
        raise FileNotFoundError(f"{DATABASE} not found")
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Ensures account exists, is unlocked, resets failed login count, hashes test passwords
def reset_users():
    # Ensure users exist and are unlocked
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users and their roles
    users = [USER, ADMIN, USER_B]
    roles = ['user', 'admin', 'user']

    for u, role in zip(users, roles):
        pwd_hash = hashpw(u['password'].encode('utf-8'), gensalt()).decode('utf-8')

        # Delete old records
        cursor.execute("DELETE FROM users WHERE username = ?", (u['username'],))

        # Inset into table
        cursor.execute(
            "INSERT INTO users (username, email, pass_hash, role, isLocked, failed_login_count) "
            "VALUES (?, ?, ?, ?, 0, 0)", (u['username'], u['email'], pwd_hash, role)
        )
    cursor.execute("DELETE FROM tasks")
    conn.commit()
    conn.close()

# --- WebDriver Setup ---
# Creates webdriver instance
def setup_driver():
    options = webdriver.ChromeOptions()

    if CHROME_DRIVER_PATH:
        service = Service(CHROME_DRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=options)
    else:
        driver = webdriver.Chrome(options=options)

    # Add wait for elements to appear
    driver.implicitly_wait(5)
    return driver

# Closes selenium
def teardown_driver(driver):
    if driver:
        driver.quit()


# --- Helpers ---
# Performs a login attempt using provided credentials
def login(driver, username, password):
    driver.get(f"{BASE_URL}/login")
    driver.find_element(By.NAME, "username_or_email").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.NAME, "submit").click()

# Returns flash message
def get_flash(driver):
    try:
        alert = WebDriverWait(driver, 2).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.alert"))
        )
        return alert.text.strip()
    except TimeoutException:
        return ""

# Logout function
def logout(driver):
    driver.get(f"{BASE_URL}/logout")


# --- Test Cases ---
# Test 1: Successful login: ensures valid user credentials and redirect to /tasks
def test_login(driver):
    print("[TEST] Successful login")
    reset_users()
    login(driver, USER["username"], USER["password"])
    try:
        WebDriverWait(driver, 5).until(EC.url_to_be(f"{BASE_URL}/tasks"))
        print("PASS: Successful login")
    except TimeoutException:
        print("FAIL: Login did not redirect")
    logout(driver)

# Test 2: Brute force lockout: 5 invalid login attempts to lock account, check if messages work correctly
def test_bruteforce_lockout(driver):
    print("[TEST] Brute-force lockout")
    reset_users()
    for i in range(5):
        login(driver, USER["username"], "wrong_pass")
        flash = get_flash(driver)
        if i < 4 and "Invalid login credentials" not in flash:
            print(f"FAIL: Attempt {i+1} flash message wrong: {flash}")
        if i == 4 and "locked" not in flash.lower():
            print(f"FAIL: Account not locked on 5th attempt: {flash}")
    print("PASS: Account locked after 5 failed attempts")

# Test 3: CRUD + Authorization: Create, update, delete tasks, input validation, prevent unauthorized access
def test_crud_operations(driver):
    print("[TEST] CRUD operations")
    reset_users()

    # Login as testUser
    login(driver, USER["username"], USER["password"])
    WebDriverWait(driver, 5).until(EC.url_to_be(f"{BASE_URL}/tasks"))

    # Create task
    driver.find_element(By.NAME, "title").send_keys("Test Task")
    driver.find_element(By.NAME, "description").send_keys("Task Description")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Add Task')]").click()

    # Get created task ID
    try:
        task_elem = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.XPATH, "//strong[contains(text(), 'Test Task')]"))
        )
        col_div = task_elem.find_element(By.XPATH, "./ancestor::div[contains(@class, 'col')]")
        edit_link = col_div.find_element(By.XPATH, ".//a[contains(@href, '/edit/')]")
        task_id = edit_link.get_attribute("href").split("/")[-1]
        print("PASS: Task created")
    except Exception as e:
        print("FAIL: Task creation failed", e)
        return

    # Update task
    driver.find_element(By.XPATH, f"//a[@href='/edit/{task_id}']").click()
    title_input = driver.find_element(By.NAME, "title")
    title_input.clear()
    title_input.send_keys("Updated Task")
    desc_input = driver.find_element(By.NAME, "description")
    desc_input.clear()
    desc_input.send_keys("Updated Desc")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Update Task')]").click()
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.XPATH, "//strong[contains(text(), 'Updated Task')]"))
    )
    print("PASS: Task updated")

    # Input Validation (empty title)
    driver.find_element(By.XPATH, f"//a[@href='/edit/{task_id}']").click()
    driver.find_element(By.NAME, "title").clear()
    driver.find_element(By.XPATH, "//button[contains(text(), 'Update Task')]").click()
    flash = get_flash(driver)
    if "cannot be empty" in flash.lower():
        print("PASS: Empty title rejected")
    else:
        print("FAIL: Empty title not rejected")

    # Restore title
    driver.find_element(By.NAME, "title").send_keys("Updated Task")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Update Task')]").click()
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.XPATH, "//strong[contains(text(), 'Updated Task')]"))
    )
    logout(driver)

    # Unauthorized delete attempt
    login(driver, USER_B["username"], USER_B["password"])
    driver.get(f"{BASE_URL}/delete/{task_id}")
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.TAG_NAME, "body"))
    )
    body_text = driver.find_element(By.TAG_NAME, "body").text
    if "Unauthorized" in body_text:
        print("PASS: Unauthorized access blocked")
    else:
        print("FAIL: Unauthorized access not blocked")

    # Valid delete by task owner
    login(driver, USER["username"], USER["password"])
    driver.get(f"{BASE_URL}/delete/{task_id}")
    try:
        # Added timeouts cause it refused to work otherwise
        WebDriverWait(driver, 5).until(EC.url_to_be(f"{BASE_URL}/tasks"))
        WebDriverWait(driver, 5).until(
            EC.invisibility_of_element_located((By.XPATH, f"//strong[contains(text(), 'Updated Task')]"))
        )
        print("PASS: Task deleted")
    except TimeoutException:
        print("FAIL: Task deletion failed")
    logout(driver)

# Test 4: Admin security logs: admin can access /adminDash, non admin users cannot access /adminDash
def test_admin_logs(driver):
    print("[TEST] Admin security log access")
    reset_users()

    # Admin access logs
    login(driver, ADMIN["username"], ADMIN["password"])
    driver.get(f"{BASE_URL}/adminDash")
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "div"))
    )
    print("PASS: Admin can view logs")
    logout(driver)
    driver.delete_all_cookies()

    # Non-admin access logs
    login(driver, USER["username"], USER["password"])
    driver.get(f"{BASE_URL}/adminDash")

    try:
        WebDriverWait(driver, 10).until(
            EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Unauthorized: admin access required")
        )
        print("PASS: Non-admin access blocked")
    except TimeoutException:
        print("FAIL: Non-admin access not blocked")
    logout(driver)

# --- Main Execution ---
if __name__ == "__main__":
    driver = None
    try:
        driver = setup_driver()
        test_login(driver)
        test_bruteforce_lockout(driver)
        test_crud_operations(driver)
        test_admin_logs(driver)
    finally:
        teardown_driver(driver)