import re
import os
from bs4 import BeautifulSoup

facebook_link = "https://facebook.com/test_page"
twitter_link = "https://x.com/test_page"

def mirror_layout_rtl(input_filepath, output_filepath):
    with open(input_filepath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    # Precision CSS targeting only top-level navigation and structural flex rows
    precision_mirror_css = """
    /* 1. Only reverse top-level navigation and explicit row classes */
    header, nav, .row, .flex-row, ul.menu, .nav-items {
        display: flex !important;
        flex-direction: row-reverse !important;
    }

    /* 2. Reverse header/navigation text and float alignment */
    header, nav {
        text-align: right !important;
    }

    /* 3. Re-enforce original width and block display for main content containers */
    main, section, article, .container, .card, [class*="card"], [class*="wrapper"] {
        flex-direction: column; /* Preserve vertical stacking inside cards */
        width: 100%;
        max-width: 100%;
    }

    /* 4. Flip floating elements safely */
    [style*="float: left"] { float: right !important; }
    [style*="float: right"] { float: left !important; }
    """

    style_tag = soup.new_tag('style', id='precision-mirror-rules')
    style_tag.string = precision_mirror_css

    if soup.head:
        soup.head.append(style_tag)

    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(str(soup))

def update_color_scheme_vars(input_filepath, output_filepath):
    with open(input_filepath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    dark_mode_css = """
    body {
        background-color: #121212 !important;
        color: #e0e0e0 !important;
    }
    a {
        color: #bb86fc !important;
    }
    div, section, article, header, footer, nav {
        background-color: inherit;
        color: inherit;
    }
    """

    style_tag = soup.new_tag('style')
    style_tag.string = dark_mode_css

    if soup.head:
        soup.head.append(style_tag)

    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(str(soup))

def add_social_links(input_filepath, output_filepath, fb_url, twitter_url, target_tag='body'):
    with open(input_filepath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    social_block_html = f'''
    <div class="social-links-block" style="margin-top: 20px; padding: 10px; border-top: 1px solid #ccc;">
        <p>Follow us on social media for updates: 
            <a href="{fb_url}" target="_blank" rel="noopener noreferrer">Facebook</a> | 
            <a href="{twitter_url}" target="_blank" rel="noopener noreferrer">Twitter / X</a>
        </p>
    </div>
    '''

    new_block = BeautifulSoup(social_block_html, 'html.parser')

    target_element = soup.find(target_tag)

    if target_element:
        target_element.append(new_block)
        print(f"Social links added to <{target_tag}>.")
    else:
        if soup.body:
            soup.body.append(new_block)
            print(f"Target <{target_tag}> not found. Appended to <body> instead.")

    # Save the updated HTML
    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(str(soup))

def mask_all_password_like_fields(input_filepath, output_filepath):
    with open(input_filepath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    password_pattern = re.compile(
        r'\b(pass|password|passwd|pwd|passcode|passphrase|secret|pin|auth_key|token)\b', 
        re.IGNORECASE
    )

    for input_tag in soup.find_all('input'):
        attributes_to_check = [
            input_tag.get('name', ''),
            input_tag.get('id', ''),
            input_tag.get('placeholder', ''),
            input_tag.get('autocomplete', ''),
            input_tag.get('aria-label', ''),
            ' '.join(input_tag.get('class', []))
        ]

        combined_attr = " ".join([str(attr) for attr in attributes_to_check if attr])

        if password_pattern.search(combined_attr):
            input_tag['type'] = 'password'

    cleaned_html = str(soup)
    js_unmask_pattern = re.compile(
        r'.*?\.type\s*=\s*[\'"]text[\'"].*?', 
        re.IGNORECASE
    )
    
    lines = cleaned_html.splitlines()
    filtered_lines = [
        line for line in lines 
        if not (password_pattern.search(line) and js_unmask_pattern.search(line))
    ]

    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write("\n".join(filtered_lines))

def remove_right_click_prevention(input_filepath, output_filepath):
    with open(input_filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    soup = BeautifulSoup(content, 'html.parser')
    
    attributes_to_remove = [
        'oncontextmenu', 'onkeydown', 'onkeypress', 
        'onkeyup', 'onselectstart', 'ondragstart'
    ]

    for tag in soup.find_all(True):
        for attr in attributes_to_remove:
            if attr in tag.attrs:
                del tag[attr]

    cleaned_html = str(soup)

    js_patterns = [
        r'.*addEventListener\s*\(\s*[\'"]contextmenu[\'"].*?\);?',
        r'.*oncontextmenu\s*=.*?;?',
        r'.*addEventListener\s*\(\s*[\'"]keydown[\'"].*?\);?',
        r'.*(123|73|74|67|85).*?preventDefault.*?;?',
        r'.*event\.keyCode\s*===\s*(123|73|74|67|85).*?;?'
    ]

    for pattern in js_patterns:
        cleaned_html = re.sub(pattern, '', cleaned_html, flags=re.IGNORECASE)

    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(cleaned_html)

def inspect_html_features(html_path: str) -> dict:
    """
    Parses an HTML string and extracts structural, script, form, 
    and link features for security analytics and model inspection.
    """
    base_html_path = html_path + "rendered_html.html"

    if os.path.exists(base_html_path):
        # Open and read the file contents using UTF-8 encoding
        with open(base_html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

    soup = BeautifulSoup(html_content, "html.parser")
    results = {}

    # =========================================================================
    # 1. DOM Structural Complexity & Tag Inflation Checks[cite: 1, 6, 7]
    # =========================================================================
    
    # Total Element Count (Low counts < 100 often indicate short-lived pages)[cite: 6, 81]
    all_elements = soup.find_all(True)
    results["total_dom_elements"] = len(all_elements)

    # Maximum DOM Depth Calculation
    def get_element_depth(element):
        depth = 0
        while element.parent:
            depth += 1
            element = element.parent
        return depth

    max_depth = max([get_element_depth(el) for el in all_elements], default=0)
    results["max_dom_depth"] = max_depth

    # Check for Hidden / Non-Rendering Dummy Elements (Tag Inflation)
    hidden_elements = soup.find_all(
        lambda tag: tag.has_attr("style") and 
        ("display:none" in tag["style"].replace(" ", "").lower() or 
         "visibility:hidden" in tag["style"].replace(" ", "").lower())
    )
    results["hidden_dummy_tag_count"] = len(hidden_elements)

    # Check for Transparent Text Styling
    transparent_text_elements = soup.find_all(
        lambda tag: tag.has_attr("style") and 
        "color:transparent" in tag["style"].replace(" ", "").lower()
    )
    results["transparent_text_tag_count"] = len(transparent_text_elements)

    # =========================================================================
    # 2. Form Endpoints & Input Field Attribute Checks[cite: 1, 4, 7]
    # =========================================================================
    
    forms = soup.find_all("form")
    results["form_count"] = len(forms)
    
    form_details = []
    for form in forms:
        action = form.get("action", "").strip()
        form_details.append({
            "action": action,
            # Check for generic/local handlers or empty actions[cite: 7, 53, 98]
            "is_local_or_empty_action": action in ["", "#", "local.php", "javascript:void(0)"]
        })
    results["form_details"] = form_details

    # Check for Plain-Text Password Fields (Unmasked Passwords)
    # Inspects whether input fields named or ID'd as 'password' use type='text'
    unmasked_passwords = soup.find_all(
        "input", 
        attrs={"type": "text", "name": re.compile(r"pass|pwd", re.I)}
    )
    results["unmasked_password_fields"] = len(unmasked_passwords)

    if results["unmasked_password_fields"]:
        mask_all_password_like_fields(base_html_path, html_path+"password_masked_html.html")

    # =========================================================================
    # 3. Hyperlinks, Navigation, and Client-Side Script Checks[cite: 1, 6, 7]
    # =========================================================================
    
    anchors = soup.find_all("a")
    results["total_anchor_tags"] = len(anchors)

    # Dead-end Anchor Checks (`href` set to `#`, `#skip`, `javascript:void(0)`)
    dead_end_links = [
        a.get("href") for a in anchors 
        if a.get("href", "").strip().lower() in ["#", "#skip", "#content", "javascript:void(0)", "javascript:void(0);"]
    ]
    results["dead_end_link_count"] = len(dead_end_links)

    # Script Tag Counts (Inline vs External)[cite: 1, 6, 7, 131, 151]
    scripts = soup.find_all("script")
    results["total_script_tags"] = len(scripts)
    results["external_scripts"] = len([s for s in scripts if s.has_attr("src")])
    results["inline_scripts"] = len([s for s in scripts if not s.has_attr("src")])

    # Check for Navigation / Shortcut Key Interception Scripting
    # Searches for event listeners that block right-click or source-viewing keys
    combined_script_text = " ".join([s.get_text() for s in scripts])
    results["disables_context_menu"] = "contextmenu" in combined_script_text and "preventDefault" in combined_script_text
    results["disables_inspection_keys"] = any(
        key in combined_script_text for key in ["F12", "F11", "Ctrl", "ctrlKey"]
    ) and "preventDefault" in combined_script_text

    if results["disables_context_menu"] or results["disables_inspection_keys"]:
        remove_right_click_prevention(base_html_path, html_path+"right_click_enabled_html.html")

    # =========================================================================
    # 4. Footer & Asset Array Inclusions[cite: 4, 7, 10]
    # =========================================================================
    
    footer = soup.find("footer")
    if footer:
        footer_images = footer.find_all("img")
        results["footer_image_count"] = len(footer_images)
    else:
        results["footer_image_count"] = 0

    # =========================================================================
    # 5. Visual Changes
    # =========================================================================
    
    add_social_links(base_html_path, html_path+"social_links_added.html", facebook_link, twitter_link)
    
    update_color_scheme_vars(base_html_path, html_path+"color_changed.html")

    mirror_layout_rtl(base_html_path, html_path+"mirrored.html")

    return results


if __name__ == "__main__":
    html_path = "/home/user/Desktop/Isiah_Projects/Scam_Research/Results/https:/coopswipe.com/2026_10_10_23_09/"

    features = inspect_html_features(html_path)
    
    print("--- HTML Feature Extraction Results ---")
    for key, value in features.items():
        print(f"{key}: {value}")