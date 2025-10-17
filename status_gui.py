# -*- coding: utf-8 -*-
import pandas as pd
from fuzzywuzzy import fuzz
from datetime import datetime
import re
import xlsxwriter
import configparser
import sys
import os
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

MIN_WORD_LENGTH = 3
MIN_RATIO_SCORE = 60
RATIO_THRESHOLD_2 = 85
MIN_OUTPUT_INDEX = 1
WORD_MATCH_COUNT_THRESHOLD = 60
MIN_WORD_COUNT_FOR_OUTPUT = 1

def get_prefix_match_threshold(word):
    length = len(word)
    if length < 5: return 1.0
    if length < 10: return 0.9
    return 0.8

def calculate_prefix_match_ratio(s1, s2):
    min_len = min(len(s1), len(s2))
    if min_len == 0: return 0.0
    match_count = 0
    for i in range(min_len):
        if s1[i] == s2[i]:
            match_count += 1
        else:
            break
    return match_count / len(s1)

def get_status_from_config(product_string, da_mapping, linux_mapping, status_mapping):
    clean_product = product_string.lower()
    vendor, product = '', ''
    if ',' in product_string:
        parts = product_string.split(',', 1); vendor, product = parts[0].strip(), parts[1].strip()
    elif '-' in product_string:
        parts = product_string.split('-', 1); vendor, product = parts[0].strip(), parts[1].strip()
    else:
        product = product_string.strip()
    vuln_vendor_lower, vuln_product_lower = vendor.lower(), product.lower()
    search_parts = [clean_product, vuln_vendor_lower, vuln_product_lower]
    def check_config_mapping(mapping):
        for key_phrase, value in mapping.items():
            if key_phrase and any(key_phrase in part for part in search_parts if part):
                return key_phrase, value
        return None, None
    key_s, val_s = check_config_mapping(status_mapping)
    if key_s:
        status, product_id = val_s; return status, product_id, "KnownSTATUS Config", key_s
    key_d, product_id = check_config_mapping(da_mapping)
    if key_d: return "ДА", product_id, "KnownDA Config", key_d
    key_l, product_id = check_config_mapping(linux_mapping)
    if key_l: return "ЛИНУКС", product_id, "KnownLINUX Config", key_l
    return "", "", "", ""

def load_and_preprocess_ppts_data(local_path, general_path, cols_l, cols_g):
    try:
        df_local = pd.read_excel(local_path, header=None, usecols=cols_l, dtype=str)
        df_local.columns = ['ID_PPTS', 'Product_PPTS', 'Vendor_PPTS']; df_local['Source_PPTS'] = 'Local PPTS'
        df_general = pd.read_excel(general_path, header=None, usecols=cols_g, dtype=str)
        df_general.columns = ['ID_PPTS', 'Product_PPTS', 'Vendor_PPTS']; df_general['Source_PPTS'] = 'General PPTS'
    except ValueError as e: raise Exception(f"Ошибка при чтении столбцов ППТС: {e}")
    except FileNotFoundError as e: raise FileNotFoundError(f"Файл ППТС не найден: {e.filename}")
    df_ppts = pd.concat([df_local, df_general], ignore_index=True); df_ppts = df_ppts.fillna('')
    return df_ppts

def normalize_string_words(s):
    global MIN_WORD_LENGTH
    if not s: return set()
    s = re.sub(r'\d+', '', s); s = re.sub(r'[^\w\s]', ' ', s.lower())
    return {w for w in s.split() if len(w) >= MIN_WORD_LENGTH}

def get_word_match_stats(words_src, words_ppts):
    global WORD_MATCH_COUNT_THRESHOLD
    if not words_src or not words_ppts: return 0.0, 0
    max_score = 0.0
    good_matches_count = 0
    for w_src in words_src:
        best_ratio_for_word = 0
        required_prefix_ratio = get_prefix_match_threshold(w_src)
        for w_ppts in words_ppts:
            ratio = fuzz.ratio(w_src, w_ppts)
            if ratio >= WORD_MATCH_COUNT_THRESHOLD:
                actual_prefix_ratio = calculate_prefix_match_ratio(w_src, w_ppts)
                if actual_prefix_ratio >= required_prefix_ratio:
                    if ratio > best_ratio_for_word:
                        best_ratio_for_word = ratio
        if best_ratio_for_word > max_score:
            max_score = best_ratio_for_word
        if best_ratio_for_word >= WORD_MATCH_COUNT_THRESHOLD:
            good_matches_count += 1
    return max_score, good_matches_count

def get_new_match_index(vendor_score, product_score):
    global MIN_RATIO_SCORE, RATIO_THRESHOLD_2
    n1, n2 = MIN_RATIO_SCORE, RATIO_THRESHOLD_2
    v1, p1 = vendor_score >= n1, product_score >= n1
    v2, p2 = vendor_score >= n2, product_score >= n2
    if v2 and p2: return 4
    if v1 and p1: return 3
    if v2 or p2: return 2
    if v1 or p1: return 1
    return 0

def find_new_strict_matches(vuln_product_str, ppts_df):
    global MIN_OUTPUT_INDEX, MIN_WORD_COUNT_FOR_OUTPUT
    src_vendor, src_product = '', ''
    if ',' in vuln_product_str:
        parts = vuln_product_str.split(',', 1); src_vendor, src_product = parts[0].strip(), parts[1].strip()
    elif '-' in vuln_product_str:
        parts = vuln_product_str.split('-', 1); src_vendor, src_product = parts[0].strip(), parts[1].strip()
    else:
        src_product = vuln_product_str.strip()
    src_vendor_words = normalize_string_words(src_vendor)
    src_product_words = normalize_string_words(src_product)
    matches = []
    for index, row in ppts_df.iterrows():
        ppts_vendor, ppts_product = str(row['Vendor_PPTS']), str(row['Product_PPTS'])
        ppts_id = row['ID_PPTS']
        ppts_vendor_words = normalize_string_words(ppts_vendor)
        ppts_product_words = normalize_string_words(ppts_product)
        vendor_score, vendor_word_count = get_word_match_stats(src_vendor_words, ppts_vendor_words)
        product_score, product_word_count = get_word_match_stats(src_product_words, ppts_product_words)
        match_index = get_new_match_index(vendor_score, product_score)
        total_word_count = vendor_word_count + product_word_count
        if match_index == 0:
            if (not ppts_vendor and src_vendor_words) or (not ppts_product and src_product_words):
                ppts_combined_words = ppts_vendor_words.union(ppts_product_words)
                src_combined_words = src_vendor_words.union(src_product_words)
                combined_score, combined_word_count = get_word_match_stats(src_combined_words, ppts_combined_words)
                match_index = get_new_match_index(combined_score, 0)
                vendor_score, product_score = combined_score, 0
                total_word_count = combined_word_count
        if match_index >= MIN_OUTPUT_INDEX and total_word_count >= MIN_WORD_COUNT_FOR_OUTPUT:
            display_name = f"{row['Vendor_PPTS']} - {row['Product_PPTS']}".strip(' - ')
            sort_score = max(vendor_score, product_score)
            matches.append({'display_name': display_name, 'index': match_index, 'vendor_score': vendor_score, 'product_score': product_score, 'sort_score': sort_score, 'id': ppts_id, 'source': row['Source_PPTS'], 'matched_word_count': total_word_count})
    matches.sort(key=lambda x: (x['index'], x['matched_word_count'], x['sort_score']), reverse=True)
    return matches

class OutputRedirector:
    def __init__(self, text_widget, status_var):
        self.text_widget = text_widget; self.status_var = status_var; self.stdout_backup = sys.stdout; sys.stdout = self
    def write(self, s):
        self.text_widget.insert(tk.END, s); self.text_widget.see(tk.END); self.text_widget.update_idletasks()
    def flush(self): pass
    def update_status(self, message): self.status_var.set(message)
    def restore(self): sys.stdout = self.stdout_backup

def analyze_data(app_instance, config_data):
    global MIN_WORD_LENGTH, MIN_RATIO_SCORE, RATIO_THRESHOLD_2, MIN_OUTPUT_INDEX, WORD_MATCH_COUNT_THRESHOLD, MIN_WORD_COUNT_FOR_OUTPUT
    app_instance.redirector.update_status("Начало анализа...")
    try:
        MIN_WORD_LENGTH = int(config_data['min_word_length']); MIN_RATIO_SCORE = int(config_data['min_ratio_score']); RATIO_THRESHOLD_2 = int(config_data['ratio_threshold_2']); MIN_OUTPUT_INDEX = int(config_data['min_output_index']); WORD_MATCH_COUNT_THRESHOLD = int(config_data['word_match_count_threshold']); MIN_WORD_COUNT_FOR_OUTPUT = int(config_data['min_word_count_for_output'])
        cols_l = [int(x.strip()) for x in config_data['ppts_local_columns'].split(',')]; cols_g = [int(x.strip()) for x in config_data['ppts_general_columns'].split(',')]
        known_da_mapping_raw = dict(re.findall(r"(.+?)\s*=\s*([^\n]+)", config_data['known_da'], re.IGNORECASE)); known_da_mapping = {k.lower().strip(): v.strip() for k, v in known_da_mapping_raw.items()}
        known_status_mapping_raw = dict(re.findall(r"(.+?)\s*=\s*([^\n]+)", config_data['known_status'], re.IGNORECASE)); known_status_mapping = {}
        for key, val in known_status_mapping_raw.items():
            parts = [x.strip() for x in val.split(',')];
            if len(parts) >= 2: known_status_mapping[key.lower()] = (parts[0].upper(), parts[1])
        known_linux_mapping_raw = dict(re.findall(r"(.+?)\s*=\s*([^\n]+)", config_data['known_linux'], re.IGNORECASE)); known_linux_mapping = {k.lower().strip(): v.strip() for k, v in known_linux_mapping_raw.items()}
        print("Чтение исходных файлов..."); df_vuln = pd.read_excel(config_data['file_vulnerabilities'], dtype=str).fillna('')
        df_ppts = load_and_preprocess_ppts_data(config_data['file_ppts_local'], config_data['file_ppts_general'], cols_l, cols_g)
        print("Анализ уязвимостей..."); main_table_data = []; detailed_analysis_list = []
        today_date = datetime.now().strftime('%d.%m.%Y'); df_vuln.columns = ['№', 'CVE', 'CVSS', 'Продукт', 'Источник']
        vuln_counter = 1; total_rows = len(df_vuln)
        for index, row in df_vuln.iterrows():
            app_instance.redirector.update_status(f"Обработано: {index + 1}/{total_rows} строк...")
            product_to_check = str(row.get('Продукт', ''))
            config_result = get_status_from_config(product_to_check, known_da_mapping, known_linux_mapping, known_status_mapping)
            config_status, config_id_ppts, config_source_type, config_key_phrase = config_result
            status, id_ppts, source_info = "", "", ""; new_matches_list = find_new_strict_matches(product_to_check, df_ppts)
            final_id_ppts = "-----------"; final_source_info = ""
            status_is_set = False
            is_da_config = config_status == "ДА"
            if is_da_config:
                status = "ДА"; final_id_ppts = config_id_ppts; final_source_info = config_source_type
                status_is_set = True
            if not status_is_set and config_status and config_status.startswith("УСЛОВНО"):
                status = "УСЛОВНО"; final_id_ppts = config_id_ppts; final_source_info = config_source_type
                status_is_set = True
            if not status_is_set and config_status == "ЛИНУКС":
                matches_conflicting = [m for m in new_matches_list if m['index'] >= 2]
                if not matches_conflicting:
                    status = "ЛИНУКС"; final_id_ppts = config_id_ppts; final_source_info = config_source_type
                elif new_matches_list:
                    status = ""; best_match = new_matches_list[0]; final_id_ppts = best_match['id']; final_source_info = best_match['source']
                status_is_set = True
            if not status_is_set:
                if not new_matches_list:
                    status = "НЕТ"; final_id_ppts = "-----------"; final_source_info = ""
                else:
                    status = ""; best_match = new_matches_list[0]; final_id_ppts = best_match['id']; final_source_info = best_match['source']
            id_ppts = final_id_ppts if status else ""; source_info = final_source_info if status else ""
            main_row = {'№': row.get('№', ''), 'Дата обработки': today_date, 'Ответственный': '', 'Публикация': '', 'Статус': status, 'ID ППТС': id_ppts, 'CVE': row.get('CVE', ''), 'CVSS': row.get('CVSS', ''), 'Продукт': product_to_check, 'Источник': row.get('Источник', '')}
            main_table_data.append(main_row)
            detailed_status = config_status if config_status else ("НАЙДЕНО" if new_matches_list else "НЕТ")
            if config_status:
                status_for_detailed = f"{config_status} (Ключ: {config_key_phrase})"; id_for_detailed = f"{config_id_ppts} (Источник: {config_source_type})"
            else: status_for_detailed, id_for_detailed = '', ''
            vuln_info_row = {'№': vuln_counter, 'CVE': row.get('CVE', ''), 'CVSS': row.get('CVSS', ''), 'Продукт': product_to_check, 'Источник': row.get('Источник', ''), 'Статус из конфига': status_for_detailed, 'ID ППТС из конфига': id_for_detailed, 'Matches': new_matches_list, '_status_for_formatting': detailed_status}
            detailed_analysis_list.append(vuln_info_row); vuln_counter += 1
        print("\nФормирование отчета Excel..."); df_main = pd.DataFrame(main_table_data)
        index_explanation = {'Индекс': [0, 1, 2, 3, 4, ''], 'Пояснение': ['Нет совпадений (отсечено)', f'Лучшее слово совпало на >= {MIN_RATIO_SCORE}% ТОЛЬКО в Вендоре или ТОЛЬКО в Продукте', f'Лучшее слово совпало на >= {RATIO_THRESHOLD_2}% ТОЛЬКО в Вендоре или ТОЛЬКО в Продукте', f'Лучшие слова совпали на >= {MIN_RATIO_SCORE}% и в Вендоре, и в Продукте', f'Лучшие слова совпали на >= {RATIO_THRESHOLD_2}% и в Вендоре, и в Продукте', f'Примечание (Индекс вывода >= {MIN_OUTPUT_INDEX})'], 'Доп. Инфо': [f'Выводятся только совпадения с индексом >= {MIN_OUTPUT_INDEX} и кол-вом слов >= {MIN_WORD_COUNT_FOR_OUTPUT}', 'Сортировка по кол-ву слов > T%, затем по %.', 'Сортировка по кол-ву слов > T%, затем по %.', 'Сортировка по кол-ву слов > T%, затем по %.', 'Сортировка по кол-ву слов > T%, затем по %.', 'T - порог для подсчета слов (задается в GUI).']}
        df_index = pd.DataFrame(index_explanation)
        base_name, ext = os.path.splitext(config_data['output_file_path']); output_file_final = f"{base_name}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}{ext if ext else '.xlsx'}"
        with pd.ExcelWriter(output_file_final, engine='xlsxwriter') as writer:
            df_main.to_excel(writer, sheet_name='Основная таблица', index=False); workbook = writer.book
            header_format = workbook.add_format({'bold': True, 'text_wrap': True, 'valign': 'top', 'fg_color': '#D7E4BC', 'border': 1}); green_format = workbook.add_format({'bg_color': '#C6EFCE', 'border': 1}); gray_format = workbook.add_format({'bg_color': '#D3D3D3', 'border': 1}); wrap_format = workbook.add_format({'text_wrap': True, 'valign': 'top'}); match_index_bold = workbook.add_format({'bold': True}); match_wrap_format = workbook.add_format({'text_wrap': True, 'valign': 'top'})
            worksheet_detailed = writer.book.add_worksheet('Детальный анализ')
            detailed_headers = ['№', 'CVE', 'CVSS', 'Продукт', 'Источник', 'Статус из конфига', 'ID ППТС из конфига', 'ID ППТС (найденный)', 'Совпадение (Имя, Индекс)', 'Доп. Инфо ППТС']
            worksheet_detailed.write_row('A1', detailed_headers, header_format)
            row_num = 1
            for vuln_data in detailed_analysis_list:
                status = vuln_data.get('_status_for_formatting')
                current_format = None
                if status:
                    if status in ["ДА", "НЕТ", "ЛИНУКС"] or status.startswith("УСЛОВНО"): current_format = green_format
                    elif status == "НАЙДЕНО": current_format = gray_format
                base_cell_format = current_format if current_format else wrap_format
                base_data = [vuln_data['№'], vuln_data['CVE'], vuln_data['CVSS'], vuln_data['Продукт'], vuln_data['Источник'], vuln_data['Статус из конфига'], vuln_data['ID ППТС из конфига'], '', '', '']
                worksheet_detailed.write_row(row_num, 0, base_data, base_cell_format); worksheet_detailed.set_row(row_num, None, base_cell_format); row_num += 1
                for i, match in enumerate(vuln_data['Matches']):
                    parts = [match_index_bold, f"({match['index']}) ", match_wrap_format, f"\"{match['display_name']}\""]
                    extra_info = f"Вендор: {match['vendor_score']:.1f}%, Продукт: {match['product_score']:.1f}%, Слов > {WORD_MATCH_COUNT_THRESHOLD}%: {match['matched_word_count']}, Источник: {match['source']}"
                    empty_cols = [''] * 7; match_row_format = wrap_format
                    worksheet_detailed.write_row(row_num, 0, empty_cols, match_row_format)
                    worksheet_detailed.write_string(row_num, 7, match['id'], match_row_format); worksheet_detailed.write_rich_string(row_num, 8, *parts, match_row_format); worksheet_detailed.write_string(row_num, 9, extra_info, match_row_format)
                    worksheet_detailed.set_row(row_num, None, match_row_format); row_num += 1
            df_index.to_excel(writer, sheet_name='Справка по индексам', index=False)
            worksheet_main = writer.sheets['Основная таблица']; worksheet_main.set_column('A:J', 15); worksheet_main.set_column('I:I', 40)
            worksheet_detailed.set_column('A:A', 5); worksheet_detailed.set_column('B:B', 20); worksheet_detailed.set_column('C:C', 10); worksheet_detailed.set_column('D:D', 35); worksheet_detailed.set_column('E:E', 25); worksheet_detailed.set_column('F:F', 20); worksheet_detailed.set_column('G:G', 40); worksheet_detailed.set_column('H:H', 20); worksheet_detailed.set_column('I:I', 40); worksheet_detailed.set_column('J:J', 60);
            worksheet_index = writer.sheets['Справка по индексам']; worksheet_index.set_column('A:D', 40)
        print(f"\nОбработка завершена. Результаты сохранены в файл: {output_file_final}")
    except Exception as e:
        print(f"\nКРИТИЧЕСКАЯ ОШИБКА: {e}")
    finally:
        app_instance.run_button.config(state=tk.NORMAL)

class Application(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("Утилита анализа статусов уязвимостей"); self.geometry("1200x800")
        self.file_vars = {'file_vulnerabilities': tk.StringVar(value=""), 'file_ppts_local': tk.StringVar(value=""), 'file_ppts_general': tk.StringVar(value=""), 'status_config_file': tk.StringVar(value=""), 'output_file_path': tk.StringVar(value="output_report.xlsx")}
        self.processing_status = tk.StringVar(value="Ожидание..."); self.create_widgets(); self.redirector = OutputRedirector(self.log_text, self.processing_status)
    def _bind_text_widgets(self, widget):
        def _copy(event):
            try: widget.clipboard_clear(); widget.clipboard_append(widget.selection_get())
            except: pass
            return "break"
        def _paste(event):
            try: widget.insert(tk.INSERT, widget.clipboard_get())
            except: pass
            return "break"
        def _select_all(event):
            try: widget.tag_add(tk.SEL, "1.0", tk.END); widget.mark_set(tk.INSERT, "1.0")
            except: pass
            return "break"
        widget.bind('<Control-c>', _copy); widget.bind('<Control-v>', _paste); widget.bind('<Control-a>', _select_all)
        widget.bind('<Command-c>', _copy); widget.bind('<Command-v>', _paste); widget.bind('<Command-a>', _select_all)
    def create_widgets(self):
        main_frame = tk.Frame(self, padx=10, pady=10); main_frame.pack(fill=tk.BOTH, expand=True)
        config_frame = tk.LabelFrame(main_frame, text="Настройки и Файлы", padx=10, pady=10); config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        file_frame = tk.LabelFrame(config_frame, text="Выбор файлов", padx=5, pady=5); file_frame.pack(fill=tk.X)
        self._create_file_selector(file_frame, "Уязвимости (Input):", 'file_vulnerabilities', False); self._create_file_selector(file_frame, "ППТС Локал. (Input):", 'file_ppts_local', False); self._create_file_selector(file_frame, "ППТС Общий (Input):", 'file_ppts_general', False)
        self._create_file_selector(file_frame, "Конфиг Статусов:", 'status_config_file', False, self._load_status_config, [("Text files", "*.txt"), ("All files", "*.*")]); self._create_file_selector(file_frame, "Отчет (Output):", 'output_file_path', True)
        settings_frame = tk.LabelFrame(config_frame, text="Настройки WordMatching и Columns", padx=5, pady=5); settings_frame.pack(fill=tk.X, pady=5)
        tk.Label(settings_frame, text="Колонки ППТС Локал (L):").grid(row=0, column=0, sticky="w"); self.cols_l_entry = tk.Entry(settings_frame, width=15); self.cols_l_entry.insert(0, "14, 16, 19"); self.cols_l_entry.grid(row=0, column=1, sticky="w")
        tk.Label(settings_frame, text="Колонки ППТС Общий (G):").grid(row=1, column=0, sticky="w"); self.cols_g_entry = tk.Entry(settings_frame, width=15); self.cols_g_entry.insert(0, "12, 14, 17"); self.cols_g_entry.grid(row=1, column=1, sticky="w")
        tk.Label(settings_frame, text="Мин. длина слова:").grid(row=2, column=0, sticky="w"); self.min_len_entry = tk.Entry(settings_frame, width=5); self.min_len_entry.insert(0, "3"); self.min_len_entry.grid(row=2, column=1, sticky="w")
        tk.Label(settings_frame, text="Порог 1 (%):").grid(row=3, column=0, sticky="w"); self.ratio_1_entry = tk.Entry(settings_frame, width=5); self.ratio_1_entry.insert(0, "60"); self.ratio_1_entry.grid(row=3, column=1, sticky="w")
        tk.Label(settings_frame, text="Порог 2 (%):").grid(row=4, column=0, sticky="w"); self.ratio_2_entry = tk.Entry(settings_frame, width=5); self.ratio_2_entry.insert(0, "85"); self.ratio_2_entry.grid(row=4, column=1, sticky="w")
        tk.Label(settings_frame, text="Мин. Индекс вывода:").grid(row=5, column=0, sticky="w"); self.min_idx_entry = tk.Entry(settings_frame, width=5); self.min_idx_entry.insert(0, "1"); self.min_idx_entry.grid(row=5, column=1, sticky="w")
        tk.Label(settings_frame, text=f"Порог слов >T% (60%):").grid(row=6, column=0, sticky="w"); self.word_count_thresh_entry = tk.Entry(settings_frame, width=5); self.word_count_thresh_entry.insert(0, "60"); self.word_count_thresh_entry.grid(row=6, column=1, sticky="w")
        tk.Label(settings_frame, text="Мин. кол-во слов:").grid(row=7, column=0, sticky="w"); self.min_word_count_entry = tk.Entry(settings_frame, width=5); self.min_word_count_entry.insert(0, "1"); self.min_word_count_entry.grid(row=7, column=1, sticky="w")
        config_data_frame = tk.LabelFrame(config_frame, text="Конфигурационные данные", padx=5, pady=5); config_data_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        tk.Label(config_data_frame, text="[KnownSTATUS] (Статус, ID):").pack(fill=tk.X); self.known_status_text = scrolledtext.ScrolledText(config_data_frame, height=5); self.known_status_text.pack(fill=tk.X); self._bind_text_widgets(self.known_status_text)
        tk.Label(config_data_frame, text="[KnownDA] (ID):").pack(fill=tk.X); self.known_da_text = scrolledtext.ScrolledText(config_data_frame, height=5); self.known_da_text.pack(fill=tk.X); self._bind_text_widgets(self.known_da_text)
        tk.Label(config_data_frame, text="[KnownLINUX] (ID):").pack(fill=tk.X); self.known_linux_text = scrolledtext.ScrolledText(config_data_frame, height=5); self.known_linux_text.pack(fill=tk.X); self._bind_text_widgets(self.known_linux_text)
        output_frame = tk.Frame(main_frame, padx=10, pady=10); output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        log_label = tk.Label(output_frame, text="Лог обработки (включая ошибки):"); log_label.pack(fill=tk.X); self.log_text = scrolledtext.ScrolledText(output_frame, height=30, state=tk.NORMAL); self.log_text.pack(fill=tk.BOTH, expand=True)
        control_frame = tk.Frame(output_frame, pady=10); control_frame.pack(fill=tk.X)
        self.run_button = tk.Button(control_frame, text="СТАРТ АНАЛИЗА", command=self.start_analysis_thread, height=2); self.run_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        status_label = tk.Label(control_frame, text="Статус:", padx=10); status_label.pack(side=tk.LEFT); self.status_bar = tk.Label(control_frame, textvariable=self.processing_status, bd=1, relief=tk.SUNKEN, anchor=tk.W, width=50); self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
    def _create_file_selector(self, parent, label_text, var_key, is_save, callback=None, filetypes=None):
        frame = tk.Frame(parent); frame.pack(fill=tk.X, pady=2)
        tk.Label(frame, text=label_text, width=20, anchor="w").pack(side=tk.LEFT)
        entry = tk.Entry(frame, textvariable=self.file_vars[var_key], width=50); entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        btn_text = "Выбрать..." if not is_save else "Указать путь..."; command = lambda: self._select_file(var_key, is_save, callback, filetypes); tk.Button(frame, text=btn_text, command=command).pack(side=tk.LEFT)
    def _select_file(self, var_key, is_save, callback=None, filetypes=None):
        initial_file = self.file_vars[var_key].get(); initial_dir = os.path.dirname(initial_file) if initial_file else os.getcwd()
        if is_save: file_path = filedialog.asksaveasfilename(initialdir=initial_dir, defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")], initialfile=os.path.basename(initial_file) if initial_file else "output_report.xlsx")
        else: final_filetypes = filetypes if filetypes else [("Excel files", "*.xlsx"), ("All files", "*.*")]; file_path = filedialog.askopenfilename(initialdir=initial_dir, filetypes=final_filetypes)
        if file_path:
            self.file_vars[var_key].set(file_path)
            if callback: callback(file_path)
    def _load_status_config(self, file_path):
        if not file_path: return
        try:
            config_parser = configparser.ConfigParser(allow_no_value=True); config_parser.read_string("[DEFAULT]\n" + open(file_path, 'r', encoding='utf-8').read())
            def get_section_text(section_name):
                if section_name.upper() in config_parser: return "\n".join([f"{k} = {v}" if v is not None else k for k, v in config_parser.items(section_name.upper())])
                return ""
            status_text = get_section_text('KnownSTATUS'); self.known_status_text.delete('1.0', tk.END); self.known_status_text.insert(tk.END, status_text)
            da_text = get_section_text('KnownDA'); self.known_da_text.delete('1.0', tk.END); self.known_da_text.insert(tk.END, da_text)
            linux_text = get_section_text('KnownLINUX'); self.known_linux_text.delete('1.0', tk.END); self.known_linux_text.insert(tk.END, linux_text)
            self.redirector.write(f"Конфигурация статусов успешно загружена из {os.path.basename(file_path)}\n")
        except Exception as e: messagebox.showerror("Ошибка загрузки конфига", f"Не удалось загрузить или разобрать файл конфигурации: {e}")
    def start_analysis_thread(self):
        config_data = {'file_vulnerabilities': self.file_vars['file_vulnerabilities'].get(), 'file_ppts_local': self.file_vars['file_ppts_local'].get(), 'file_ppts_general': self.file_vars['file_ppts_general'].get(), 'output_file_path': self.file_vars['output_file_path'].get(), 'ppts_local_columns': self.cols_l_entry.get(), 'ppts_general_columns': self.cols_g_entry.get(), 'min_word_length': self.min_len_entry.get(), 'min_ratio_score': self.ratio_1_entry.get(), 'ratio_threshold_2': self.ratio_2_entry.get(), 'min_output_index': self.min_idx_entry.get(), 'word_match_count_threshold': self.word_count_thresh_entry.get(), 'min_word_count_for_output': self.min_word_count_entry.get(), 'known_status': self.known_status_text.get('1.0', tk.END), 'known_da': self.known_da_text.get('1.0', tk.END), 'known_linux': self.known_linux_text.get('1.0', tk.END)}
        required_files = ['file_vulnerabilities', 'file_ppts_local', 'file_ppts_general', 'output_file_path']
        if not all(self.file_vars[k].get() for k in required_files): messagebox.showerror("Ошибка", "Необходимо выбрать все входные и выходной файлы!"); return
        self.run_button.config(state=tk.DISABLED); self.log_text.delete('1.0', tk.END); self.processing_status.set("Идет подготовка...")
        analysis_thread = threading.Thread(target=analyze_data, args=(self, config_data)); analysis_thread.start()

if __name__ == '__main__':
    try:
        app = Application()
        app.mainloop()
    except Exception as e:
        if 'app' in locals() and hasattr(app, 'redirector'): app.redirector.restore()
        raise
