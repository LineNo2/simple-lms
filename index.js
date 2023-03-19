const express = require('express');
const mysql = require('mysql');
const dbconfig = require('./config/database.js');
const bodyParser = require('body-parser');
const connection = mysql.createConnection(dbconfig);
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const app = express();

const isHTTPS = false;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.set('port', process.env.PORT || 6125);

async function verifyToken(req) {
  const token = req.cookies.token;
  if(!token){
	return false;
  }
  const decodedToken = await jwt.verify(token, process.env.JWT_SECRET);
  return decodedToken;
}

app.get('/', (req, res) => {
  const token = req.cookies.token;
  if(!token){
	res.redirect('/login');
	return;
  }

  jwt.verify(token, 'secret_key', (err, decoded) => {
	if(err) {
	  res.clearCookie('token');
	  res.redirect('/');
	  return;
	}
	const id = decoded.id;
	const name = decoded.name;
	const univ_id = decoded.univ_id;
	const is_pf = decoded.is_pf;
	console.log(id, name, univ_id, is_pf);
	if(is_pf){
	  connection.query('SELECT * FROM Courses WHERE pf_id = ?',[univ_id],(err, courses) => {
		if(err) {res.send('서버 오류 발생.');return}
		let courseName = {}
		courses.forEach((value) => {
		  courseName[value.course_id] = value.class_name;
		});
		courseName = JSON.stringify(courseName);
		fs.readFile('./lib/html/main-pf.html', 'utf8', (err, html) => {
		  res.send(eval('`' + html + '`'));
		});
	  });
	}
	else{
	  connection.query('SELECT * FROM Enrollment JOIN Courses ON Enrollment.course_id = Courses.course_id WHERE univ_id',[univ_id],(err, courses) => {
		if(err) {res.send('서버 오류 발생.');return}
		let courseName = {}
		courses.forEach((value) => {
		  courseName[value.course_id] = value.class_name;
		});
		courseName = JSON.stringify(courseName);
		fs.readFile('./lib/html/main-st.html', 'utf8', (err, html) => {
		  res.send(eval('`' + html + '`'));
		});
	  });
	}
  });
});

app.get('/view-course', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  const courseID = req.query.course_id;
	connection.query('SELECT * FROM Posts WHERE course_id = ?', [courseID], (err, posts) => {
	  if(err){
		console.log(err);
		res.status(400).send('현재 서버 문제로 인해 조회가 되지 않습니다.');
		return;
	  }
	  res.send(posts);
  });
});

app.post('/create-post', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  const courseID = req.body.course_id;
  const title = req.body.title;
  const body = req.body.body;
  const univID = decodedToken.univ_id;
  console.log(courseID, title, body);
  connection.query('SELECT * FROM Courses WHERE course_id = ? AND pf_id = ?', [courseID, univID], (err, result) => {
	if(err) { 
	  res.status(400).send('서버 문제로 제출할 수 없습니다.');
	  console.log(err);
	  return
	}
	if(result.length == 0){
	  res.status(400).send('존재하지 않는 수업입니다.');
	  return
	}
	connection.query('INSERT INTO Posts(course_id, title, body, created_at) VALUES(?,?,?,NOW())', [courseID, title, body], (err, result) => {
	  if(err) { 
		res.status(400).send('서버 문제로 제출할 수 없습니다.');
		console.log(err);
		return
	  }
	  res.send('성공적으로 제출 되었습니다.');
	});
  });
});

app.post('/delete-post', async (req, res) => {
  const postID = req.body.post_id;
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  connection.query('DELETE FROM Posts WHERE post_id = ?',[postID], (err, result) => {
	if(err) { 
	  res.status(400).send('서버 문제로 삭제할 수 없습니다.');
	  console.log(err);
	  return
	}
	res.send('성공적으로 삭제 되었습니다.');
  });
});

app.post('/create-course', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(401).send('로그인이 안되어있습니다.');
	return;
  }
  const courseID = req.body.course_id;
  const courseName = req.body.course_name;
  if(!RegExp(/[A-Z]{4}[0-9]{3}/g).test(courseID)){
	res.status(406).send('잘못된 강의 코드 형식입니다!');
	return;
  }
  if(courseName == ''){
	res.status(406).send('강의 이름이 비어있습니다!');
	return;
  }
  const univID = decodedToken.univ_id;
  connection.query('INSERT INTO Courses VALUES(?,?,?)', [courseID, univID, courseName], (err, result) => {
	if(err){ 
	  if(err.code == 'ER_DUP_ENTRY'){
		res.status(409).send('이미 존재하는 강의입니다.');
	  }
	  else{
		res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  }
	  return;
	}
	res.send('성공적으로 제출 되었습니다.');
  });
});

app.get('/login', (req, res) => {
  fs.readFile('./lib/html/login.html', 'utf8', (err, data) => {
	if(err) {
	  console.error('login.html 파일이 없습니다!');
	  return;
	}
	res.send(data);
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.send('로그아웃 완료!');
});

app.get('/register', (req, res) => {
  fs.readFile('./lib/html/register.html', 'utf8', (err, html) => {
	res.send(html);
  });
});

app.post('/register', (req, res) => {
  data = req.body;
  let  { isPassed, msg } = validateRegistrationData(data); 
  if(isPassed){
	connection.query('SELECT * FROM Users WHERE id = ? OR univ_id = ?',[data.id, data.univId], (err, result) => {
	  if (err) return console.log(err);
	  if(result.length > 0){
		res.status(400).send( result[0].id === data.id ? '중복된 아이디 입니다.' : '이미 가입된 학번입니다.'); 
	  }
	  else{
		const {salt, hash} = encryptPassword(data.pw);
		const query = 'INSERT INTO Users (id, hash, name, univ_id, is_pf) VALUES (?, ?, ?, ?, ?)';
		console.log([data.id, salt + ':' + hash, data.name, data.univId, data.isPf]);
		connection.query(query, [data.id, salt + ':' + hash, data.name, data.univId, data.isPf], (err) => {
		  if (err) {
			console.log('Register 실패!');
			console.log(err);
			return;
		  }
		  res.send('회원가입에 성공했습니다!');
		});
	  }
	});
	return;
  }
  res.status(400).send(msg);
});

app.post('/login', (req, res) => {
  const { id, pw } = req.body;
  console.log(id, pw);
  connection.query('SELECT * FROM Users WHERE id = ?', [id], (err, result) => {
	if(err){
	  res.status(400).send('서버의 상태가 좋지 않습니다.');
	  return;
	}
	if(result.length == 0){
	  res.status(401).send('존재하지 않는 계정입니다!');
	  return;
	}
	const salt = result[0].hash.split(':')[0];
	const hash = result[0].hash.split(':')[1];
	const univ_id = result[0].univ_id;
	const name = result[0].name;
	const is_pf = result[0].is_pf;
	const isPasswordCorrect = verifyPassword(pw, hash, salt);
	if(isPasswordCorrect){
	  const user = {id : id, name : name, univ_id : univ_id, is_pf : is_pf};
	  const token = jwt.sign(user, 'secret_key', {expiresIn : '1h'});
	  console.log(user);
	  res.cookie('token', token, {httpOnly : true, secure : isHTTPS});
	  res.send('로그인 성공!');
	}
	else{
	  res.status(401).send('로그인 실패!');
	}
  });
});


app.post('/student-list', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  const courseID = req.body.course_id;
  connection.query('SELECT Users.univ_id, name FROM Enrollment JOIN Users ON Enrollment.univ_id = Users.univ_id WHERE course_id = ? ', [courseID], (err, result) => {
	if(err){ 
	  res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  return;
	}
	console.log(result.length);
	res.send(JSON.stringify(result));
  });
});

app.post('/search', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  const keyword = req.body.keyword + '%';
  connection.query('SELECT course_id, class_name, name FROM Courses JOIN Users ON pf_id = univ_id WHERE course_id like ? or class_name like ? or name like ?', [keyword,keyword,keyword], (err, result) => {
	if(err){ 
	  res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  return;
	}
	console.log(result.length);
	res.send(JSON.stringify(result));
  });
});

app.post('/enroll', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(400).send('로그인이 안되어있습니다.');
	return;
  }
  const univID = decodedToken.univ_id;
  const isPf = decodedToken.is_pf;
  const courseID = req.body.course_id;
  if (isPf) {
	res.status(400).send('교수님은 수강신청을 할 수 없습니다.');
  }
  connection.query('SELECT * FROM Enrollment WHERE univ_id = ? and course_id = ?',[univID, courseID], (err, result) => {
	if(err){
	  res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  return;
	}
	if(result.length > 0){
	  res.status(409).send('이미 신청하신 강의입니다.');
	  return;
	}
	connection.query('INSERT INTO Enrollment(univ_id, course_id) VALUES(?,?)', [univID, courseID], (err, result) => {
	  if(err){
		res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  }
	  res.send('신청에 성공했습니다!');
	});
  });
});

app.post('/drop', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(401).send('로그인이 안되어있습니다.');
	return;
  }
  const univID = req.body.univ_id ? req.body.univ_id :  decodedToken.univ_id;
  const courseID = req.body.course_id;
  console.log(univID, courseID);
  connection.query('DELETE FROM Enrollment WHERE univ_id = ? AND course_id = ?', [univID, courseID], (err, result) => {
	if(err){
	  res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  return;
	}
	res.send('완료되었습니다.');
  });
});

app.post('/stream-post', async (req, res) => {
  const decodedToken = await verifyToken(req);
  if (!decodedToken) {
	res.status(401).send('로그인이 안되어있습니다.');
	return;
  }
  const univID = decodedToken.univ_id;
  connection.query(' SELECT Posts.course_id, title, body, created_at, class_name FROM Enrollment JOIN Posts ON Enrollment.course_id = Posts.course_id JOIN Courses ON Posts.course_id = Courses.course_id WHERE univ_id = ? ORDER BY 4 DESC', [univID], (err, result) => {
	if(err){
	  res.status(400).send('서버 문제로 오류가 발생했습니다.');
	  return;
	}
	res.send(JSON.stringify(result));
  });
});

app.listen(app.get('port'), () => {
  console.log(app.get('port'));
});

function validateRegistrationData(data) {
  const { id, pw, name, univId, isPf } = data;

  if (!validateId(id)) {
	return { isPassed: false, msg: "ID는 5글자 이상, 영문과 숫자만 사용 가능합니다." };
  }

  if (!validatePw(pw)) {
	return { isPassed: false, msg: "비밀번호는 5글자 이상, 영문과 숫자만 사용 가능합니다."};
  }

  if (!validateName(name)) {
	return { isPassed: false, msg: "이름은 영문 또는 한글만 가능합니다." };
  }

  if (!validateUnivId(univId)) {
	return { isPassed: false, msg: "학번은 숫자, 길이 10입니다." };
  }

  if (!validateIsPf(isPf)) {
	return { isPassed: false, msg: "올바르지 않은 구분입니다." };
  }


  return { isPassed: true };
}

function validateId(id) {
  const regex = /^[a-zA-Z0-9]{5,}$/;
  return regex.test(id);
}

function validatePw(pw) {
  const regex = /^[a-zA-Z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]+$/;
  return regex.test(pw); }

function validateName(name) {
  const regex = /^[a-zA-Z가-힣]+$/;
  return regex.test(name);
}

function validateUnivId(univId) {
  console.log(univId);
  const regex = /^[0-9]{10}$/;
  return regex.test(univId);
}

function validateIsPf(isPf) {
  return isPf == 0 || isPf == 1;
}

function encryptPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex'); 
  const hash = crypto.pbkdf2Sync(pw, salt, 1000, 64, 'sha512').toString('hex'); // 비밀번호와 솔트를 이용해 해시 생성
  return {
    salt,
    hash
  };
}

function verifyPassword(pw, hash, salt) {
  const hashVerify = crypto.pbkdf2Sync(pw, salt, 1000, 64, 'sha512').toString('hex'); 
  return hash == hashVerify; 
}
