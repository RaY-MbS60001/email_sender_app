import json
import random
from datetime import datetime, timedelta
import re
from typing import List, Dict, Union
import hashlib

class LearnershipsGenerator:
    def __init__(self):
        self.categories = {
            "IT & Technology": {
                "programs": [
                    "Software Development",
                    "Cloud Computing",
                    "Cybersecurity",
                    "Data Analytics",
                    "Network Engineering",
                    "AI & Machine Learning",
                    "Web Development",
                    "Mobile App Development",
                    "IT Support",
                    "Systems Administration"
                ],
                "keywords": ["tech", "software", "it", "cyber", "digital", "data", "systems", "computing"]
            },
            "Business & Finance": {
                "programs": [
                    "Business Administration",
                    "Financial Management",
                    "Accounting",
                    "Business Analysis",
                    "Investment Banking",
                    "Risk Management",
                    "Corporate Finance",
                    "Business Operations",
                    "Enterprise Development",
                    "Commercial Management"
                ],
                "keywords": ["business", "finance", "accounting", "corporate", "commercial", "enterprise"]
            },
            "Engineering": {
                "programs": [
                    "Mechanical Engineering",
                    "Electrical Engineering",
                    "Civil Engineering",
                    "Chemical Engineering",
                    "Industrial Engineering",
                    "Engineering Design",
                    "Process Engineering",
                    "Manufacturing Engineering",
                    "Automation Engineering",
                    "Quality Engineering"
                ],
                "keywords": ["engineering", "mechanical", "electrical", "technical", "industrial"]
            },
            "Healthcare & Medical": {
                "programs": [
                    "Healthcare Management",
                    "Medical Administration",
                    "Clinical Support",
                    "Healthcare Operations",
                    "Medical Technology",
                    "Pharmaceutical Services",
                    "Healthcare Support",
                    "Medical Practice Management",
                    "Health Information Management",
                    "Patient Care Services"
                ],
                "keywords": ["health", "medical", "clinical", "patient", "pharma", "care"]
            },
            "Digital Marketing": {
                "programs": [
                    "Digital Marketing Strategy",
                    "Social Media Management",
                    "Content Marketing",
                    "SEO & SEM",
                    "Email Marketing",
                    "Digital Advertising",
                    "Marketing Analytics",
                    "Brand Management",
                    "E-commerce Marketing",
                    "Digital Communications"
                ],
                "keywords": ["marketing", "digital", "brand", "advertising", "media"]
            }
        }

        self.company_types = [
            "Limited", "Pty Ltd", "Corporation", "Solutions", 
            "Group", "Technologies", "Services", "International",
            "Incorporated", "Consultancy"
        ]

        self.locations = {
            "Gauteng": ["Johannesburg", "Pretoria", "Sandton", "Midrand", "Centurion"],
            "Western Cape": ["Cape Town", "Stellenbosch", "Paarl", "Somerset West"],
            "KwaZulu-Natal": ["Durban", "Pietermaritzburg", "Richards Bay"],
            "Eastern Cape": ["Port Elizabeth", "East London"],
            "Free State": ["Bloemfontein"],
            "Remote": ["Remote Work", "Hybrid"]
        }

        self.requirements = {
            "basic": [
                "Valid South African ID",
                "Age 18-35",
                "Currently Unemployed",
                "No Criminal Record"
            ],
            "education": [
                "Matric Certificate",
                "National Diploma",
                "Bachelor's Degree",
                "Relevant Certification"
            ],
            "skills": [
                "Computer Literacy",
                "Communication Skills",
                "Problem-Solving Ability",
                "Team Player",
                "Critical Thinking"
            ]
        }

    def generate_company_name(self, email: str) -> str:
        """Generate a professional company name from email domain."""
        domain = email.split('@')[1].split('.')[0]
        words = re.findall('[A-Z][^A-Z]*', domain.title().replace('-', ''))
        if not words:
            words = [domain.title()]
        
        company_name = ' '.join(words)
        if random.random() < 0.5:
            company_name += f" {random.choice(self.company_types)}"
        return company_name

    def generate_unique_id(self, email: str) -> str:
        """Generate a unique ID based on email."""
        return hashlib.md5(email.encode()).hexdigest()[:8]

    def categorize_email(self, email: str) -> str:
        """Determine the most appropriate category based on email content."""
        email_lower = email.lower()
        
        for category, data in self.categories.items():
            if any(keyword in email_lower for keyword in data["keywords"]):
                return category
        
        return random.choice(list(self.categories.keys()))

    def generate_program_details(self, category: str) -> Dict:
        """Generate comprehensive program details."""
        category_data = self.categories.get(category, random.choice(list(self.categories.values())))
        program_name = random.choice(category_data["programs"])
        
        start_date = datetime.now() + timedelta(days=random.randint(30, 90))
        end_date = start_date + timedelta(days=random.randint(180, 730))

        return {
            "name": program_name,
            "duration_months": random.randint(6, 24),
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "positions_available": random.randint(5, 50),
            "stipend_range": f"R{random.randint(3, 8)}000 - R{random.randint(8, 15)}000",
            "application_deadline": (start_date - timedelta(days=14)).strftime("%Y-%m-%d")
        }

    def generate_location_info(self) -> Dict:
        """Generate detailed location information."""
        province = random.choice(list(self.locations.keys()))
        city = random.choice(self.locations[province])
        
        return {
            "province": province,
            "city": city,
            "work_type": random.choice(["On-site", "Hybrid", "Remote"])
        }

    def generate_requirements(self, category: str) -> Dict:
        """Generate specific requirements based on category."""
        basic_reqs = random.sample(self.requirements["basic"], k=random.randint(2, 4))
        edu_reqs = random.sample(self.requirements["education"], k=random.randint(1, 2))
        skill_reqs = random.sample(self.requirements["skills"], k=random.randint(2, 4))

        return {
            "basic_requirements": basic_reqs,
            "educational_requirements": edu_reqs,
            "skill_requirements": skill_reqs,
            "additional_requirements": [
                f"Experience in {category} is advantageous",
                "Strong analytical skills",
                "Ability to work independently"
            ]
        }

    def create_learnership_entry(self, email: str, index: int) -> Dict:
        """Create a comprehensive learnership entry."""
        category = self.categorize_email(email)
        company_name = self.generate_company_name(email)
        program_details = self.generate_program_details(category)
        location_info = self.generate_location_info()

        return {
            "id": index,
            "unique_id": self.generate_unique_id(email),
            "company": {
                "name": company_name,
                "email": email,
                "icon": f"{company_name.lower().replace(' ', '_')}.png",
                "website": f"https://www.{email.split('@')[1]}",
                "contact_info": {
                    "email": email,
                    "tel": f"011 {random.randint(100, 999)} {random.randint(1000, 9999)}"
                }
            },
            "program": program_details,
            "category": category,
            "location": location_info,
            "requirements": self.generate_requirements(category),
            "application_process": {
                "steps": [
                    "Online Application",
                    "Document Submission",
                    "Assessment",
                    "Interview",
                    "Final Selection"
                ],
                "required_documents": [
                    "CV",
                    "ID Copy",
                    "Matric Certificate",
                    "Qualifications",
                    "Reference Letters"
                ]
            }
        }

    def generate_learnership_data(self, emails: List[str]) -> Dict:
        """Generate complete learnership dataset."""
        learnerships = []
        
        for idx, email in enumerate(emails, 1):
            learnership = self.create_learnership_entry(email, idx)
            learnerships.append(learnership)

        return {
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_learnerships": len(learnerships),
            "categories": list(self.categories.keys()),
            "learnerships": learnerships
        }

def save_to_json(data: Dict, filename: str = "learnerships.json"):
    """Save data to JSON file with proper formatting."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# Example usage
if __name__ == "__main__":
    # Your email list
    email_list = [
        "info@diversityempowerment.co.za",
        "enquiries@sparrowportal.co.za",
        "sihle.nyanga@impactful.co.za",
        "mseleke@csgskills.co.za",
        "consultant@afrec.co.za",
        "recruit@visionacademy.co.za",
        "info@theskillshub.co.za",
        "careers@rivoningoconsultancy.co.za",
        "recruitment@oks.co.za",
        "farina.bowen@i-fundi.com",
        "za031-cvapplications@msc.com",
        "funda@liberty-college.co.za",
        "ayandam@sisekelo.co.za",
        "apply@aaat.co.za",
        "hr@learnseta.online",
        "tigane@amphisa.co.za",
        "cm.gpnorthaggregate@za.afrisam.com",
        "tinyikom@ilearn.co.za",
        "prabashini@techtisa.co.za",
        "cv@fitho.co.za",
        "application@trainingforce.co.za",
        "learnerships@tidyswip.co.za",
        "brandons@nthusefoundation.co.za",
        "cv@amplerecruitment.co.za",
        "cv@i-people.co.za",
        "recruitment3@factsa.co.za",
        "recruitment@ikworx.co.za",
        "recruitment@apdjhb.co.za",
        "query@skilltechsa.co.za",
        "qualitycontrol@camblish.co.za",
        "queen@bpchrsolutions.co.za",
        "walter.mngomezulu@ctutraining.co.za",
        "work@u-belong.co.za",
        "recruitment@estudysa.co.za",
        "ayo@zignatrainingonline.co.za",
        "amelia@cdpa.co.za",
        "cv@afrec.co.za",
        "recruit@afrec.co.za",
        "recruitment@afrec.co.za",
        "cvs@afrec.co.za",
        "training2@bidvestcatering.co.za",
        "faith.khethani@cdasolutions.co.za",
        "culinary.recruitment@tigerbrands.com",
        "learners@telebest.co.za",
        "ginab@access4all-sa.co.za",
        "cv@glu.co.za",
        "ilze@glu.co.za",
        "csshr@csssolutions.co.za",
        "genevieve@advancedassessments.co.za",
        "jonas@aaat.co.za",
        "infoct@primeserv.co.za",
        "recruitmentofficer@teacademy.co.za",
        "training@retshepeng.co.za",
        "recruitment@kdstraining.co.za",
        "learn@cowhirlacademy.co.za",
        "recruitment@roahconsulting.co.za",
        "admin@kbonengconsulting.co.za",
        "victory@nzconsultancts.co.za",
        "leratomoraba@aaat.co.za",
        "learnership@stratism.co.za",
        "recruitment@mpowersmart.co.za",
        "lucyc@afrikatikkun.org",
        "info@wethinkcode.co.za",
        "justice.seupe@bschool.edu.za",
        "sdf1@teacademy.co.za",
        "nmakazi@afrikanbank.co.za",
        "trainingcentre.admin@blindsa.org.za",
        "data.admin@pro-learn.co.za",
        "learnerships@skillsjunction.co.za",
        "achievement@friends4life.co.za",
        "hr@dialadude.co.za",
        "ibmskillsbuild.emea@skilluponline.com",
        "info@snergy.co.za",
        "samukelo@saentrepreneurshipempowerment.org.za",
        "yes@signa.co.za",
        "info@edu-wize.co.za",
        "elsie@edu-wize.co.za",
        "recruit@4ys.co.za",
        "olwethu@leapco.co.za",
        "offer@leapco.co.za",
        "cv@learnex.co.za",
        "hello@innovationadvance.co.za",
        "talent@dynamicdna.co.za",
        "nombulelo@ncpd.org.za",
        "lebohang.matlala@siyayaskills.co.za",
        "learnerships@transcend.co.za",
        "vusumuzig@ilearn.co.za",
        "cv@barnne.com",
        "recruitment@sasseta.org",
        "hr@wpxsolutions.com",
        "kruger@amphisa.co.za",
        "faneleg@tihsa.co.za",
        "pokellom@afrikatikkun.org",
        "recruitment@swiftskillsacademy.co.za",
        "refiloe@skillspanda.co.za",
        "nalini.cuppusamy@ican-sa.co.za",
        "placements@gcc-sd.com",
        "trainingcenter@ehhassim.co.za",
        "recruitment-parktown@anovahealth.co.za",
        "tshepisom@ilearn.co.za",
        "faisexam@moonstoneinfo.co.za",
        "recruitment@phosaane.co.za",
        "luzuko@lethatsiptyltd.co.za",
        "info@cbm-training.co.za",
        "recruit@bradshawleroux.co.za",
        "info@hrctraining.co.za",
        "support@beeempowermentservices.co.za",
        "lesegos@shimrag.co.za",
        "kgomotso.modiba@transunion.com",
        "lebo.makgale@gijima.com",
        "tumelo@eshybrand.co.za",
        "learners@kunaku.co.za",
        "recruitment@affinityservices.co.za",
        "gugulethu@cbm-traning.co.za",
        "gccalearners@transunion.com",
        "maria@questcollege.org.za",
        "info@micentre.co.za",
        "palesa@cbm-training.co.za",
        "info@consultingbybongi.com",
        "learn@trainingportal.co.za",
        "info@gcc-sd.co.za",
        "sales@retshepeng.co.za",
        "it@retshepeng.co.za",
        "precious@tych.co.za",
        "farhana@progression.co.za",
        "recruitment@qasa.co.za",
        "recruitment@tlo.co.za",
        "slindile@dibanisaleaening.co.za",
        "anatte@trictalent.co.za",
        "tai@noviaone.com",
        "kgotso@edgexec.co.za",
        "kagiso@related-ed.co.za",
        "skills@rma.edu.co.za",
        "nkhensani@signa.co.za",
        "joyce@learnex.co.za",
        "cornelia@xbo.co.za",
        "primrose.mathe@nicasiaholdings.co.za",
        "recruitment@sts-africa.co.za",
        "sifiso.ntamane@bsisteel.com",
        "recruitment@progression.co.za",
        "applications@moderncentric.co.za",
        "smacaulay@dynamicdna.co.za",
        "reception@dekra.co.za",
        "patience@questcollege.co.za",
        "karenm@moderncentric.co.za",
        "ivys@octopi-renewed.co.za",
        "training2@eagle-ess.co.za",
        "mpumi.m@ibusa.co.za",
        "learnership@rmvsolutions.co.za",
        "info@talentdevelooment.co.za",
        "unathi.mbiyoza@transcend.co.za",
        "helga@seesa.co.za",
        "admin@skillsempire.co.za",
        "kutlwano.mothibe@fostermelliar.co.za",
        "teddym@alefbetlearning.com",
        "rika@pendula.co.za",
        "admin@sizaabantu.co.za",
        "lorenzo@cbm-training.co.za",
        "winile@cbm-training.co.za",
        "maria@serr.co.za",
        "sdube@csgskills.co.za",
        "kagisom@moderncentric.co.za",
        "recruitment@sita.co.za",
        "kelvi.c@muditraining.co.za",
        "ntombi.zondo@netcampus.com",
        "mary.carelse@netcampus.com",
        "divan@edupowersa.co.za",
        "info@tlo.co.za",
        "admin4@liquorbarn.co.za",
        "zena@kingrec.co.za",
        "hal@fennell.co.za",
        "info@spforge.co.za",
        "careers@directaxis.co.za",
        "yasmin.theron@benteler.com",
        "pe@masa.co.za",
        "feziwe@masa.co.za",
        "kasina.sithole@adcorpblu.co.za",
        "enquiries@formex.co.za",
        "byoyophali@formex.co.za",
        "zandile@q-plas.co.za",
        "contact@lumotech.co.za",
        "belcorp@belessex.co.za",
        "portelizabeth@workforce.co.za",
        "lucilleh@quest.co.za",
        "reception@toppersonnel.co.za",
        "rosanne@mpc.co.za",
        "claire@onlinepersonnel.co.za",
        "nicola.monsma@kelly.co.za",
        "sandi@jrrecruitment.co.za",
        "nomsa@ikamvarecruitment.co.za",
        "tracy@abantustaffingsolutions.co.za",
        "wayne@alphalabour.co.za",
        "jackiec@thomas.co.za",
        "nakitap@capacity.co.za",
        "natalie@colven.co.za",
        "admin@headhunt.co.za",
        "focus@icon.co.za",
        "admin@qsafrica.co.za",
        "chantal@crsolutions.co.za",
        "zukiswa.nogqala@bell-mark.co.za",
        "nokuthula.ndamase@popup.co.za",
        "tsholofelo@seonyatseng.co.za",
        "info@tnelectrical.co.za",
        "adminb@aaaa.co.za",
        "reception@ubuhlehr.co.za",
        "vettinginternship@sita.co.za",
        "leanerships@careersit.co.za",
        "melvin@tjhbusiness.co.za",
        "recruitment@learnerspherecd.co.za",
        "alex@odinfin.co.za",
        "manaka.ramukuvhati@platinumlife.co.za",
        "info@seonyatseng.co.za",
        "application@tlo.co.za",
        "loren@metanoiagroup.co.za",
        "r1@edu-wize.co.za",
        "recruitment@advancedassessments.co.za",
        "angelique.haskins@enpower.co.za",
        "jhbsourcing@ican-sa.co.za",
        "projects@talentdevelopment.co.za",
        "training1@providingskills.co.za",
        "thando@providingskills.co.za",
        "info@camblish.co.za",
        "youniversity@brightrock.co.za",
        "admin@heartsolutions.co.za",
        "rnyoka@starschools.co.za",
        "malvinn@moderncentric.co.za",
        "operations2@skillsbureau.co.za",
        "sphiwe@xtensiveict.co.za",
        "learnerships@engenoil.com",
        "ouma@glu.co.za",
        "pretty.dlamini@ican-sa.co.za",
        "skills@vistech.co.za",
        "mpho.moletsane@goldrurush.co.za",
        "recruitment@hciskills.co.za",
        "boitumelo.makhubela@pmi-sa.co.za",
        "talent@skillsbureau.co.za",
        "training@vitalonline.co.za",
        "admin@compareaquote.co.za",
        "cv@besec.co.za",
        "trainme@estudysa.co.za"
    ]

    # Generate data
    generator = LearnershipsGenerator()
    learnership_data = generator.generate_learnership_data(email_list)
    
    # Save to file
    save_to_json(learnership_data)
    
    # Print summary
    print(f"Generated {learnership_data['total_learnerships']} learnership entries")
    print(f"Categories: {', '.join(learnership_data['categories'])}")