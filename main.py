from xss import *

testText = [
                '<script>alert(\'xss\')</script><script><script>',
                'hellomo',
                'https://store.bentley.com/en/shop/search?term=%22%3E%3Cdetails%20open%20ontoggle=prompt(1337)%3ExxLouisLouisLouis',
                'ghfdhgdhjgd',
                'uid%3D19%26list_page%3D%22%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C/script%3E',
                '&template=en_search_error&postalCode=\\\';alert(0)//',
                '&where=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E&loctypes=1003%2C1001%2C1000%2C1%2C9%2C5%2C11%2C13%2C19%2C20&from=hdr_localsearch',
                'http://mydata.com/sad/sd/qwd/qwde/qwe/?sessionid=12',
                'http://mydata.com?id=script',
                '&\';}},{scope:\'email,user_about_me,user_hometown,user_interests,user_likes,user_status,user_website,user_birthday,publish_stream,publish_actions,offline_access\'});}alert(0);b=function(response){c=({a:{//',
                'http://myurl.com?<script',
                'http://mydata.com?script=script',
                'composite_search=1&keyword="/><script>alert("Xss:Vijayendra")</script>',
                'http://mysite.com?srtalert',
                'script',
                'alert',
                'Search=%22%3E\'%3E%3CSCRIPT%20SRC=http://br.zone-h.org/testes/xss.js%3E%3C/SCRIPT%3E?',
                'id=15%3Cscript%3Ealert%28document.cookie%29%3C/script%3E',
                'composite_search=1&keyword="/><script>alert("Xss:Vijayendra")</script>',
                'id=123&href=abdc<a<script>alert(1)',
                '<<<<<<>>>>></>,><><>',
                'alert()alert()',
                'alertalert',
                '?url=http://localhost:8888/notebooks/Documents/MachineLearning/Practical%20Machine%20Learning',
                '<script<script',
                '<scriptalert',
                'httphttphttp',
                'https://disqus.com/?ref_noscript',
                'I am a string',
                '<img src="javascript:alert(1)/>"',
                'HelloWorld!',
                'http://mysite.com?<script>',
                '<input type="text" value=`` <div/onmouseover=\'alert(471)\'>X</div>',
                '<img \x47src=x onerror="javascript:alert(324)">',
                '<a href="\xE2\x80\x87javascript:javascript:alert(183)" id="fuzzelement1">test</a>',
                '<body onscroll=javascript:alert(288)><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><input autofocus>',
                '<meta charset="mac-farsi">¼script¾javascript:alert(379)¼/script¾',
                '<HTML xmlns:xss><?import namespace=(493)s" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID=(494)s"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(420)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>'
            ]



Xnew = getVec(testText)

# make a prediction
#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)
#7 LogisticRegressionClassifier
ynew7 = loaded_model7.predict(Xnew)  #YENİ EKLENDİ.



# Initialize counts
xssCount = 0
notXssCount = 0

# Display the detailed results
for i in range(len(Xnew)):
    print(f"\n------------- Prediction for URL {i + 1} -------------")
    print(f"URL: {testXSS[i]}")
    print(f"DecisionTreeClassifier Prediction: {ynew1[i]}")
    print(f"SVC Prediction: {ynew2[i]}")
    print(f"GaussianNB Prediction: {ynew3[i]}")
    print(f"KNeighborsClassifier Prediction: {ynew4[i]}")
    print(f"RandomForestClassifier Prediction: {ynew5[i]}")
    print(f"MLPClassifier Prediction: {ynew6[i]}")
    print(f"LogisticRegression Prediction: {ynew7[i]}")

    # Calculate the overall score based on your scoring logic
    score = (
        0.175 * ynew1[i]
        + 0.15 * ynew2[i]
        + 0.05 * ynew3[i]
        + 0.075 * ynew4[i]
        + 0.25 * ynew5[i]
        + 0.3 * ynew6[i]
        + 0.2 * ynew7[i]  # Eklendiği kısım
    )
    print(f"Overall Score: {score}")

    if score >= 0.5:
        print("\033[1;31;1mXSS\033[0;0m => Detected")
        xssCount += 1  # XSS sayısını güncelle
    else:
        print("\033[1;32;1mNOT XSS\033[0;0m => Not Detected")
        notXssCount += 1  # NOT XSS sayısını güncelle

# Calculate the total counts
print("\n*------------- RESULTS -------------*")
print(f'\033[1;31;1mXSS\033[0;0m => Detected in {xssCount} URLs')
print(f'\033[1;32;1mNOT XSS\033[0;0m => Not Detected in {notXssCount} URLs')



