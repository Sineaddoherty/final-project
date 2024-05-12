const signuppage = e => {
    let fname = document.getElementById('Username').value,
         email = document.getElementById('email').value,
        pwd = document.getElementById('pass').value;

    let formData = JSON.parse(localStorage.getItem('formData')) || [];

    let exist = formData.length && 
        JSON.parse(localStorage.getItem('formData')).some(data => 
            data.fname.toLowerCase() == fname.toLowerCase() 
           
        );

    if(!exist){
        formData.push({ fname,  email, pwd });
        localStorage.setItem('formData', JSON.stringify(formData));
        document.querySelector('form').reset();
        document.getElementById('Username').focus();
        alert("Account Created.\nPlease Sign In using the link below.");
    }
    else{
        alert(" Account already made\nYou have already sigjned up");
    }
    e.preventDefault();
}

function signinpage(e) {
    let fname = document.getElementById('Username').value, pwd = document.getElementById('pass').value;
    let formData = JSON.parse(localStorage.getItem('formData')) || [];
    let exist = formData.length && 
    JSON.parse(localStorage.getItem('formData')).some(data => data.fname.toLowerCase() == fname && data.pwd.toLowerCase() == pwd);
    if(!exist){
        alert("Incorrect login ");
    }
    else{
        location.href = "{{ url_for('index') }}";
    }
    e.preventDefault();
}