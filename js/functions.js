$(function() {
	$(document).on('focusin', '.field, textarea', function() {
		if(this.title==this.value) {
			this.value = '';
		}
	}).on('focusout', '.field, textarea', function(){
		if(this.value=='') {
			this.value = this.title;
		}
	});


	var left = {
		imgFront	: -990,
		imgMid		: -990,
		imgBack		: -990,
		h3			: -990,
		h5			: -990,
		p			: -990,
		a			: -990
	}
	var current = {
		imgFront	: 649,
		imgMid		: 572,
		imgBack		: 498,
		h3			: 32,
		h5			: 32,
		p			: 32,
		a			: 32
	}
	var right = {
		imgFront	: 990,
		imgMid		: 990,
		imgBack		: 990,
		h3			: 990,
		h5			: 990,
		p			: 990,
		a			: 990
	}

	carouselInit();

	$(window).resize(function(){
		if( $(window).width() < 1023 && $(window).width() > 767 ){
			current = {
				imgFront	: 476,
				imgMid		: 425,
				imgBack		: 366,
				h3			: 10,
				h5			: 10,
				p			: 10,
				a			: 10
			}
		}

		else if( $(window).width() < 767 ){
			current = {
				imgFront	: 120,
				imgMid		: 80,
				imgBack		: 40,
				h3			: 10,
				h5			: 10,
				p			: 10,
				a			: 0
			}
		}

		else {
			current = {
				imgFront	: 649,
				imgMid		: 572,
				imgBack		: 498,
				h3			: 32,
				h5			: 32,
				p			: 32,
				a			: 32
			}
		}
		
		$("#carousel").trigger("destroy", false);
		setTimeout(function() {
			carouselInit();
			$("#carousel").trigger("currentVisible", function( items ) {
				
				items.find('img.img-front')
						.css({
							left: current.imgFront
						});

					items.find('img.img-mid')
						.css({
							left: current.imgMid
						});

					items.find('img.img-back')
						.css({
							left: current.imgBack
						});	

					items.find('h3')
						.animate({
							left: current.h3
						});

					items.find('h5')
						.animate({
							left: current.h5
						});	

					items.find('p')
						.css({
							left: current.p
						});

					items.find('a')
						.css({
							left: current.a
						});
			});
		}, 100);
	}).resize();
	
	$('#partners-slider .slider-holder2').carouFredSel({
		align: 'center',
	    items: {
			visible: "variable",
			width: "variable"
		},
		scroll: 1,
		prev: ".prev-arr",
		next: ".next-arr"
	});


	$('#navigation a.nav-btn').click(function(){
		$(this).closest('#navigation').find('ul').stop(true,true).slideToggle()
		$(this).find('span').toggleClass('active')
		return false;
	})

	function carouselInit(){
		var isScrolling = false;

		$('#carousel').carouFredSel({
			pagination: ".pagination",
			scroll	: {
				duration		: 0,
				pauseDuration	: 900,
				wipe: true
			},
			auto	: false,
			prev	: {
				button		: '#prev',
				key: 'left',
				conditions	: function() {
					return (!isScrolling);
				},
				onBefore	: function(oldI, newI) {
					isScrolling = true;

					$(this).delay(900);

					oldI.find('img.img-front')
						.delay(50)
						.animate({
							left: right.imgFront
						});

					oldI.find('img.img-mid')
						.delay(100)
						.animate({
							left: right.imgMid
						});

					oldI.find('img.img-back')
						.delay(200)
						.animate({
							left: right.imgBack
						});	

					oldI.find('h3')
						.delay(400)
						.animate({
							left: right.h3
						});

					oldI.find('h5')
						.delay(300)
						.animate({
							left: right.h5
						});	

					oldI.find('p')
						.delay(500)
						.animate({
							left: right.p
						});

					oldI.find('a')
						.delay(600)
						.animate({
							left: right.a
						});
				},
				onAfter: function(oldI, newI) {
					oldI.find('img.img-front')
						.css({
							left: current.imgFront
						});

					oldI.find('img.img-mid')
						.css({
							left: current.imgMid
						});

					oldI.find('img.img-back')
						.css({
							left: current.imgBack
						});	

					oldI.find('h3')
						.animate({
							left: current.h3
						});

					oldI.find('h5')
						.animate({
							left: current.h5
						});	

					oldI.find('p')
						.css({
							left: current.p
						});

					oldI.find('a')
						.css({
							left: current.a
						});

					newI.find('img.img-front')
						.css({
							left: left.imgFront
						}).delay(50)
						.animate({
							left: current.imgFront
						}, function() {
							isScrolling = false;
						});

					newI.find('img.img-mid')
						.css({
							left: left.imgMid
						}).delay(100)
						.animate({
							left: current.imgMid
						});

					newI.find('img.img-back')
						.css({
							left: left.imgBack
						}).delay(200)
						.animate({
							left: current.imgBack
						});	

					newI.find('h3')
						.css({
							left: left.h3
						}).delay(400)
						.animate({
							left: current.h3
						});

					newI.find('h5')
						.css({
							left: left.h5
						}).delay(300)
						.animate({
							left: current.h5
						});	

					newI.find('p')
						.css({
							left: left.p
						}).delay(500)
						.animate({
							left: current.p
						});

					newI.find('a')
						.css({
							left: left.a
						}).delay(600)
						.animate({
							left: current.a
						});
				}
			},
			next	: {
				button		: '#next',
				key: 'right',
				conditions	: function() {
					return (!isScrolling);
				},
				onBefore	: function(oldI, newI) {
					isScrolling = true;

					$(this).delay(900);

					oldI.find('img.img-front')
						.delay(600)
						.animate({
							left: left.imgFront
						});

					oldI.find('img.img-mid')
						.delay(500)
						.animate({
							left: left.imgMid
						});	

					oldI.find('img.img-back')
						.delay(400)
						.animate({
							left: left.imgBack
						});

					oldI.find('h3')
						.delay(100)
						.animate({
							left: left.h3
						});

					oldI.find('h5')
						.delay(50)
						.animate({
							left: left.h5
						});	

					oldI.find('p')
						.delay(200)
						.animate({
							left: left.p
						});

					oldI.find('a')
						.delay(300)
						.animate({
							left: left.a
						});
				},
				onAfter: function(oldI, newI) {
					oldI.find('img.img-front')
						.css({
							left: current.imgFront
						});

					oldI.find('img.img-mid')
						.css({
							left: current.imgMid
						});

					oldI.find('img.img-back')
						.css({
							left: current.imgBack
						});	

					oldI.find('h3')
						.animate({
							left: current.h3
						});

					oldI.find('h5')
						.animate({
							left: current.h5
						});	

					oldI.find('p')
						.css({
							left: current.p
						});

					oldI.find('a')
						.css({
							left: current.a
						});

					newI.find('img.img-front')
						.css({
							left: right.imgFront
						}).delay(600)
						.animate({
							left: current.imgFront
						});

					newI.find('img.img-mid')
						.css({
							left: right.imgMid
						}).delay(500)
						.animate({
							left: current.imgMid
						});	

					newI.find('img.img-back')
						.css({
							left: right.imgBack
						}).delay(400)
						.animate({
							left: current.imgBack
						});

					newI.find('h3')
						.css({
							left: right.h3
						}).delay(100)
						.animate({
							left: current.h3
						});

					newI.find('h5')
						.css({
							left: right.h5
						}).delay(50)
						.animate({
							left: current.h5
						});	

					newI.find('p')
						.css({
							left: right.p
						}).delay(200)
						.animate({
							left: current.p
						});

					newI.find('a')
						.css({
							left: right.a
						}).delay(300)
						.animate({
							left: current.a
						}, function() {
							isScrolling = false;
						});
				}
			}
		});
	}
});