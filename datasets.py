"""Fictional business records and reserved-domain email identities for the demo."""
import csv
import io
import secrets

SCENARIOS = ('projects', 'customers', 'payroll')
FIRST_NAMES = ('Maya', 'Ravi', 'Alex', 'Jordan', 'Priya', 'Sam', 'Nora', 'Arjun', 'Leah', 'Omar', 'Aisha', 'Theo')
LAST_NAMES = ('Shah', 'Morgan', 'Patel', 'Chen', 'Reed', 'Singh', 'Brooks', 'Kim', 'Ali', 'Rao', 'Park', 'Diaz')
COMPANIES = ('northstar', 'cedarworks', 'bluehaven', 'riverstone', 'maplefield', 'oakridge')
CUSTOMERS = r'C:\Users\Demo\Business\customers.csv'
PAYROLL = r'C:\Users\Demo\Business\payroll.csv'
CUSTOMER_BRIEF = r'C:\Users\Demo\Documents\customer_handover.txt'
PAYROLL_BRIEF = r'C:\Users\Demo\Documents\payroll_schedule.txt'
BUSINESS_PATHS = (CUSTOMERS, PAYROLL, CUSTOMER_BRIEF, PAYROLL_BRIEF)
TOPICS = {
    'projects': ('team schedule', 'project update', 'event planning', 'design feedback', 'meeting follow-up'),
    'customers': ('customer onboarding handover', 'support rota planning', 'customer success meeting', 'service follow-up schedule'),
    'payroll': ('payroll cutoff reminder', 'timesheet submission schedule', 'month-end HR handover', 'payroll calendar review'),
}


def identity():
    first, last = secrets.choice(FIRST_NAMES), secrets.choice(LAST_NAMES)
    # Reserved .test domains cannot accidentally identify a real delivery destination.
    address = f'{first.lower()}.{last.lower()}.{secrets.token_hex(3)}@{secrets.choice(COMPANIES)}.example.test'
    return dict(name=f'{first} {last}', address=address)


def csv_text(headers, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def business_files():
    customers = []
    for _ in range(12):
        person = identity()
        customers.append(['DEMO-CUST-' + secrets.token_hex(3), person['name'], person['address'],
                          secrets.choice(COMPANIES).title() + ' Demo Ltd',
                          secrets.choice(('Starter', 'Business', 'Enterprise')),
                          str(1000 + secrets.randbelow(40000)), 'DEMO-CRM-' + secrets.token_hex(8)])
    payroll = []
    for _ in range(8):
        person = identity()
        payroll.append(['DEMO-EMP-' + secrets.token_hex(3), person['name'], person['address'],
                        secrets.choice(('Engineering', 'Support', 'Operations', 'Design')),
                        str(35000 + secrets.randbelow(85000)), 'DEMO-ACCOUNT-' + secrets.token_hex(6),
                        'DEMO-TAX-' + secrets.token_hex(6)])
    return [
        dict(path=CUSTOMERS, label='Customer records', secret=True, dataset='customers', format='csv',
             content=csv_text(('customer_id', 'name', 'email', 'company', 'plan', 'annual_value_demo_inr', 'private_crm_token'), customers)),
        dict(path=PAYROLL, label='Employee payroll', secret=True, dataset='payroll', format='csv',
             content=csv_text(('employee_id', 'name', 'email', 'department', 'monthly_salary_demo_inr', 'bank_reference', 'tax_reference'), payroll)),
        dict(path=CUSTOMER_BRIEF, label='Customer handover notes', secret=False, dataset='customers',
             content='Customer onboarding handover: review the support rota on Thursday at 11 AM. Assign a coordinator for each onboarding call and confirm the follow-up schedule by Friday. This shared brief contains no individual customer records.'),
        dict(path=PAYROLL_BRIEF, label='Payroll calendar', secret=False, dataset='payroll',
             content='Payroll coordination: timesheets are due on the 24th; manager review closes on the 26th. HR meets at 2 PM on the 27th to confirm the processing calendar. This shared schedule contains no individual salaries or payment details.'),
    ]


def ensure_business_files(files):
    existing = {file['path'].casefold() for file in files}
    if any(path.casefold() not in existing for path in BUSINESS_PATHS):
        files.extend(file for file in business_files() if file['path'].casefold() not in existing)


def decoy_csv(content, token):
    """Replace every record value, retaining only field names and record count."""
    rows = list(csv.reader(io.StringIO(content)))
    replacements, decoys = {}, []
    for row_index, row in enumerate(rows[1:], 1):
        decoy_row = []
        for column, value in enumerate(row, 1):
            decoy = f'DECOY_R{row_index}_C{column}_{secrets.token_hex(4)}'
            if value:
                replacements.setdefault(value, decoy)
            decoy_row.append(replacements.get(value, decoy))
        decoys.append(decoy_row + [token])
    return csv_text(rows[0] + ['shadow_trace_token'], decoys), replacements
