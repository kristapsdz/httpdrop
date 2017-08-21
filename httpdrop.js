(function(root) {
	'use strict';

	function sendForm(e, setup, error, success, prog) 
	{
		var xmh = new XMLHttpRequest();
		var url = e.action;

		if (null !== setup)
			setup(e);

		if (null !== prog)
			xmh.upload.addEventListener("progress", function(e) {
				if (e.lengthComputable) {
					var percentage = Math.round
						((e.loaded * 100) / e.total);
					if (null !== prog)
						prog(percentage);
				}
			}, false);

		xmh.onreadystatechange=function() {
			if (xmh.readyState === 4 && 
		  	    xmh.status === 200) {
				console.log(url + ': success!');
				if (null !== success)
					success(e, xmh.responseText);
			} else if (xmh.readyState === 4) {
				console.log(url + ': failure: ' + 
					xmh.status);
				if (null !== error)
					error(e, xmh.status);
			}
		};

		xmh.open(e.method, e.action, true);
		xmh.send(new FormData(e));
		return(false);
	}

	function initFileName() 
	{
		var file, e;

		file = document.getElementById('file-name-input');
		if (null === file)
			return;
		e = document.getElementById('file-name-no-file');
		if (null !== e)
			e.className = '';
		e = document.getElementById('file-name-has-file');
		if (null !== e)
			e.className = 'hide';

		file.onchange = function() {
			if (0 === file.files.length) 
				return;
			e = document.getElementById('file-name-has-file');
			if (null !== e)
				e.className = '';
			e = document.getElementById('file-name-no-file');
			if (null !== e)
				e.className = 'hide';
		};
	}

	function initUploaderSetup() 
	{
		var e;

		e = document.getElementById('file-uploader-button');
		if (null === e) 
			return;
		e.readonly = true;
		e.innerHTML = 'Uploading: 0%';
	}

	function initUploaderProgress(percent) 
	{
		var e;

		e = document.getElementById('file-uploader-button');
		if (null === e)
			return;
		e.innerHTML = 'Uploading: ' + percent + '%';
	}

	function initUploaderFinish()
	{
		document.location.reload();
	}

	function initUploader() {
		var e;

		e = document.getElementById('file-uploader');
		if (null === e)
			return;
		console.log('here');
		e.onsubmit = function() {
			sendForm(e, 
				initUploaderSetup,
				initUploaderFinish,
				initUploaderFinish,
				initUploaderProgress);
			return(false);
		};
	}

	function initDocument() 
	{
		initUploader();
		initFileName();
	}

	root.initDocument = initDocument;
})(this);

document.addEventListener('DOMContentLoaded', initDocument);
