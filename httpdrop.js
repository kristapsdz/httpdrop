(function(root) {
	'use strict';

	/*
	 * Simple lookup function for element by name.
	 * Emits a console warning on error.
	 * Returns the element modified or null if none found.
	 */
	function find(root)
	{
		var e;

		if (typeof root !== 'string') {
			e = root;
			if (null === e)
				console.log('find: given null object');
		} else if (null === (e = document.getElementById(root)))
			console.log('find: no \'' + root + '\'');

		return(e);
	}

	function show(name)
	{
		var e;

		if (null === (e = find(name)))
			return;
		if (e.classList.contains('hide'))
			e.classList.remove('hide');
	}

	function hide(name)
	{
		var e;

		if (null === (e = find(name)))
			return;
		if ( ! e.classList.contains('hide'))
			e.classList.add('hide');
	}

	function sendForm(e, setup, error, success, prog) 
	{
		var xmh = new XMLHttpRequest();
		var url = e.action;

		if (null !== setup)
			setup(e);

		if (null !== prog)
			xmh.upload.addEventListener
			 ("progress", function(e) {
				if (e.lengthComputable) {
					var pct = Math.round
						((e.loaded * 100) / 
						 e.total);
					if (null !== prog)
						prog(pct);
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

		if (null !== (e = find('file-name-no-file')))
			e.className = '';
		if (null !== (e = find('file-name-has-file')))
			e.className = 'hide';
		if (null !== (file = find('file-name-input')))
			file.onchange = function() {
				if (0 === file.files.length) 
					return;
				e = find('file-name-has-file');
				if (null !== e)
					e.className = '';
				e = find('file-name-no-file');
				if (null !== e)
					e.className = 'hide';
			};
	}

	function initUploaderSetup() 
	{
		var e;

		if (null !== (e = find('file-uploader-button'))) {
			e.readonly = true;
			e.innerHTML = 'Uploading: 0%';
		}
	}

	function initUploaderProgress(percent) 
	{
		var e;

		if (null !== (e = find('file-uploader-button')))
			e.innerHTML = 'Uploading: ' + percent + '%';
	}

	function initUploaderFinish()
	{
		document.location.reload();
	}

	function chpassSuccess()
	{
		document.location.reload();
	}

	function chpassSetup()
	{
		hide('message-chpass-fail');
	}

	function chpassError()
	{
		show('message-chpass-fail');
	}

	function initUploader() 
	{
		var e, list, i;

		if (null !== (e = find('btn-logout')))
			e.onclick = function() {
				find('form-logout').submit();
			};
		list = document.getElementsByClassName('btn-chpass');
		for (i = 0; i < list.length; i++)
			list[i].onclick = function() {
				find('chpass-modal').classList.toggle('is-active');
				return(false);
			};
		if (null !== (e = find('file-uploader')))
			e.onsubmit = function() {
				sendForm(e, 
					initUploaderSetup,
					initUploaderFinish,
					initUploaderFinish,
					initUploaderProgress);
				return(false);
			};
		if (null !== (e = find('form-chpass')))
			e.onsubmit = function() {
				sendForm(e,
					chpassSetup,
					chpassError,
					chpassSuccess,
					null);
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
