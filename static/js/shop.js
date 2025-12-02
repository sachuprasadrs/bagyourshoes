/**
 * Unified Shop JavaScript for BagYourShoe
 * Handles: Add to Cart, Wishlist, CSRF, Notifications
 * Works for: all_shoes.html, shoes.html, all_boots.html, racing-boots.html, collection.html
 */

(function($) {
    'use strict';

    // ========================================
    // CSRF TOKEN SETUP
    // ========================================
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    const csrftoken = getCookie('csrftoken');

    // Set up CSRF for all AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });

    // ========================================
    // NOTIFICATION HELPER
    // ========================================
    function showNotification(message, type) {
        type = type || 'success';
        const $notification = $('#notification');

        if ($notification.length) {
            $notification
                .text(message)
                .removeClass('success error')
                .addClass(type)
                .addClass('show');

            setTimeout(function() {
                $notification.removeClass('show');
            }, 3000);
        } else {
            // Fallback to alert if notification div doesn't exist
            alert(message);
        }
    }

    // ========================================
    // ADD TO CART FUNCTIONALITY
    // ========================================

    // Handle form submission (for pages with size select dropdowns)
    $(document).on('submit', '.add-to-cart-form', function(e) {
        e.preventDefault();

        const $form = $(this);
        const productType = $form.data('product-type');
        const productId = $form.data('product-id');
        const $sizeSelect = $form.find('select[name="size"]');
        const $quantityInput = $form.find('input[name="quantity"]');
        const $button = $form.find('.btn-cart');

        // Get values
        const size = $sizeSelect.val();
        const quantity = parseInt($quantityInput.val() || '1', 10);

        // Validate size
        if (!size || size === '') {
            showNotification('Please select a size', 'error');
            $sizeSelect.focus();
            return false;
        }

        // Validate quantity
        if (quantity < 1) {
            showNotification('Quantity must be at least 1', 'error');
            return false;
        }

        // Add to cart
        addToCartAjax(productType, productId, size, quantity, $button);
    });

    // Handle button-only add to cart (for pages without forms)
    $(document).on('click', '.btn-cart', function(e) {
        // Check if this button is inside a form - if yes, let form handler deal with it
        if ($(this).closest('form').length > 0) {
            return; // Form will handle submission
        }

        e.preventDefault();

        const $button = $(this);
        const $item = $button.closest('.shoe-item, .product-item, .boot-item');
        const productId = $button.data('id');
        const productType = $button.data('type');

        // Try to find size from different possible locations
        let size = 'N/A';

        // Check for active size option button
        const $activeSize = $item.find('.size-option.active');
        if ($activeSize.length) {
            size = $activeSize.text().trim();
        }

        // Check for size select dropdown
        const $sizeSelect = $item.find('select[name="size"]');
        if ($sizeSelect.length && $sizeSelect.val()) {
            size = $sizeSelect.val();
        }

        // Validate that we have required data
        if (!productType || !productId) {
            showNotification('Error: Missing product information', 'error');
            console.error('Missing data-type or data-id on button:', $button);
            return false;
        }

        // Default quantity
        const quantity = 1;

        addToCartAjax(productType, productId, size, quantity, $button);
    });

    // Core AJAX function to add item to cart
    function addToCartAjax(productType, productId, size, quantity, $button) {
        // Validate inputs
        if (!productType || !productId) {
            showNotification('Error: Invalid product data', 'error');
            return;
        }

        // Disable button and show loading state
        const originalText = $button.text();
        $button.prop('disabled', true).text('Adding...');

        // Disable form inputs if within a form
        const $form = $button.closest('form');
        if ($form.length) {
            $form.find('input, select, button').prop('disabled', true);
        }

        // Make AJAX request
        $.ajax({
            url: `/add-to-cart/${productType}/${productId}/`,
            method: 'POST',
            data: {
                quantity: quantity,
                size: size,
                csrfmiddlewaretoken: csrftoken
            },
            success: function(response) {
                if (response.success) {
                    showNotification(response.message || 'Item added to cart!', 'success');
                } else {
                    showNotification(response.error || 'Could not add to cart', 'error');
                }
            },
            error: function(xhr) {
                let errorMsg = 'Error adding to cart';
                try {
                    const response = JSON.parse(xhr.responseText);
                    errorMsg = response.error || errorMsg;
                } catch(e) {
                    console.error('Failed to parse error response:', e);
                }
                showNotification(errorMsg, 'error');
            },
            complete: function() {
                // Re-enable button and restore original text
                $button.prop('disabled', false).text(originalText);

                // Re-enable form inputs if within a form
                if ($form.length) {
                    $form.find('input, select, button').prop('disabled', false);
                }
            }
        });
    }

    // ========================================
    // WISHLIST FUNCTIONALITY
    // ========================================
    $(document).on('click', '.btn-wishlist', function(e) {
        e.preventDefault();

        const $button = $(this);
        const productId = $button.data('id');
        const productType = $button.data('type');

        // Validate
        if (!productType || !productId) {
            showNotification('Error: Missing product information', 'error');
            return;
        }

        // Disable button temporarily
        $button.prop('disabled', true);

        $.ajax({
            url: `/add-to-wishlist/${productType}/${productId}/`,
            method: 'POST',
            data: {
                csrfmiddlewaretoken: csrftoken
            },
            success: function(response) {
                if (response.success) {
                    // Toggle button appearance
                    if (response.action === 'added') {
                        $button.addClass('active').html('<i class="fa fa-heart"></i>');
                    } else {
                        $button.removeClass('active').html('<i class="fa fa-heart-o"></i>');
                    }
                    showNotification(response.message, 'success');
                } else {
                    showNotification(response.error || 'Wishlist error', 'error');
                }
            },
            error: function(xhr) {
                showNotification('Failed to update wishlist', 'error');
            },
            complete: function() {
                $button.prop('disabled', false);
            }
        });
    });

    // ========================================
    // SIZE SELECTION FUNCTIONALITY
    // ========================================
    $(document).on('click', '.size-option', function() {
        $(this).siblings('.size-option').removeClass('active');
        $(this).addClass('active');
    });

    // ========================================
    // INITIALIZE ON READY
    // ========================================
    $(document).ready(function() {
        console.log('Shop.js initialized');

        // Create notification element if it doesn't exist
        if ($('#notification').length === 0) {
            $('body').append('<div class="notification" id="notification"></div>');
        }
    });

})(jQuery);
