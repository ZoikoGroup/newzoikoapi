<?php

use App\Http\Controllers\Api\CartController;
use App\Http\Controllers\Api\CartItemController;
use App\Http\Controllers\Api\EmailTemplateController;
use App\Http\Controllers\Api\OrderController;
use App\Http\Controllers\Api\OrderItemController;
use App\Http\Controllers\Api\UserAddressController;
use App\Http\Controllers\PageController;
use App\Http\Controllers\Api\ContactController;
use App\Http\Controllers\Api\AuthenticationController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\Api\ForgotPasswordController;
use App\Http\Controllers\Api\CodeCheckController;
use App\Http\Controllers\Api\ResetPasswordController;
use App\Http\Controllers\Api\ProductCategoryController;
use App\Http\Controllers\Api\ProductController;
use App\Http\Controllers\Api\DiscountTypeController;
use App\Http\Controllers\Api\ProductAttributeController;
use App\Http\Controllers\Api\CountryController;
use App\Http\Controllers\Api\StateController;
use App\Http\Controllers\Api\CityController;
use App\Http\Controllers\Api\CurrencyController;
use App\Http\Controllers\Api\FaqController;
use App\Http\Controllers\Api\MenuController;
use App\Http\Controllers\Api\MenuItemController;
use App\Http\Controllers\PlansController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
Route::post('user/update/{id}', [UserController::class, 'update'])->middleware('auth:api');

//Route::get('/get', [PageController::class, 'index']); //route for all records/pages
Route::get('/get/page/{id}', [PageController::class, 'index']);  // route for single page
Route::post('/create/page', [PageController::class, 'store'])->middleware('auth:api');
Route::delete('/delete/page/{id}', [PageController::class, 'destroy'])->middleware('auth:api');
Route::get('/get/pages/all', [PageController::class, 'all_pages'])->middleware('auth:api');
Route::post('/update/page', [PageController::class, 'update'])->middleware('auth:api');

// Contact us email and entries to database
Route::post('contact-us', [ContactController::class, 'contactusPost']);
Route::post('/get/contact/entries', [ContactController::class, 'get_messages'])->middleware('auth:api');
Route::delete('/delete/contact/entry/{id}', [ContactController::class, 'destroy'])->middleware('auth:api');

Route::middleware('auth:sanctum')->group(['namespace' => 'api', 'prefix' => 'v1'], function () {
    /*Need to disscuss with team about this*/
        // Route::post('test-api', [ApiController::class, 'api_test']);
        Route::post('login', [AuthenticationController::class, 'store']);
        Route::post('register', [AuthenticationController::class, 'register']);
        Route::get('users', [AuthenticationController::class, 'get_all_users'])->middleware('auth:api');
        Route::get('user/{id}', [AuthenticationController::class, 'show'])->middleware('auth:api');
        Route::post('user/update/{id}', [AuthenticationController::class, 'update_user'])->middleware('auth:api');
        Route::delete('user/delete/{id}', [AuthenticationController::class, 'delete_user'])->middleware('auth:api');
        Route::post('logout', [AuthenticationController::class, 'destroy'])->middleware('auth:api');

        Route::post('password/email', [ForgotPasswordController::class, '__invoke']);
        Route::post('password/code/check', [CodeCheckController::class, '__invoke']);
        Route::post('password/reset', [ResetPasswordController::class, '__invoke'])->middleware('auth:api');
    /*END Need to disscuss with team about this*/
        
    // User Address
    Route::post('address/create', [UserAddressController::class, 'store'])->middleware('auth:api');
    Route::post('address/update/{id}', [UserAddressController::class, 'update'])->middleware('auth:api');
    Route::get('addresses/user/{id}', [UserAddressController::class, 'show'])->middleware('auth:api');
    Route::delete('address/delete/{id}', [UserAddressController::class, 'destroy'])->middleware('auth:api');

    // Product Routes
    Route::get('products', [ProductController::class, 'index']);
    Route::get('product/get/{id}', [ProductController::class, 'show']);
    Route::post('product/create', [ProductController::class, 'store'])->middleware('auth:api');
    Route::post('product/update/{id}', [ProductController::class, 'update'])->middleware('auth:api');
    Route::delete('product/delete/{id}', [ProductController::class, 'destroy'])->middleware('auth:api');

    // Product Category routes
    Route::get('product/categories/', [ProductCategoryController::class, 'index']);
    Route::get('product/category/{id}', [ProductCategoryController::class, 'show']);
    Route::post('product/category/create', [ProductCategoryController::class, 'store'])->middleware('auth:api');
    Route::post('product/category/update/{id}', [ProductCategoryController::class, 'update'])->middleware('auth:api');
    Route::delete('product/category/delete/{id}', [ProductCategoryController::class, 'destroy'])->middleware('auth:api');

    // Product Discount type
    Route::get('discount/types', [DiscountTypeController::class, 'index']);
    Route::get('discount/type/{id}', [DiscountTypeController::class, 'show']);
    Route::post('discount/type/create', [DiscountTypeController::class, 'store'])->middleware('auth:api');
    Route::post('discount/type/update/{id}', [DiscountTypeController::class, 'update'])->middleware('auth:api');
    Route::delete('discount/type/delete/{id}', [DiscountTypeController::class, 'destroy'])->middleware('auth:api');

    // Product Attributes
    Route::get('pro/attributes', [ProductAttributeController::class, 'index']);
    Route::get('pro/attribute/{id}', [ProductAttributeController::class, 'show']);
    Route::post('pro/attribute/create', [ProductAttributeController::class, 'store'])->middleware('auth:api');
    Route::post('pro/attribute/update/{id}', [ProductAttributeController::class, 'update'])->middleware('auth:api');
    Route::delete('pro/attribute/delete/{id}', [ProductAttributeController::class, 'destroy'])->middleware('auth:api');

    // Countries
    Route::get('countries', [CountryController::class, 'index']);
    Route::get('country/{id}', [CountryController::class, 'show']);
    Route::post('country/create', [CountryController::class, 'store'])->middleware('auth:api');
    Route::post('country/update/{id}', [CountryController::class, 'update'])->middleware('auth:api');
    Route::delete('country/delete/{id}', [CountryController::class, 'destroy'])->middleware('auth:api');

    // States
    Route::get('states/country/{id}', [StateController::class, 'index']);
    Route::get('state/{id}', [StateController::class, 'show']);
    Route::post('state/create', [StateController::class, 'store'])->middleware('auth:api');
    Route::post('state/update/{id}', [StateController::class, 'update'])->middleware('auth:api');
    Route::delete('state/delete/{id}', [StateController::class, 'destroy'])->middleware('auth:api');

    // Cities
    Route::get('cities/state/{id}', [CityController::class, 'index']);
    Route::get('city/{id}', [CityController::class, 'show']);
    Route::post('city/create', [CityController::class, 'store'])->middleware('auth:api');
    Route::post('city/update/{id}', [CityController::class, 'update'])->middleware('auth:api');
    Route::delete('city/delete/{id}', [CityController::class, 'destroy'])->middleware('auth:api');

    // Currencies
    Route::get('currencies', [CurrencyController::class, 'index']);
    Route::get('currency/{id}', [CurrencyController::class, 'show']);
    Route::get('currency/country/{id}', [CurrencyController::class, 'get_currency']);
    Route::post('currency/create', [CurrencyController::class, 'store'])->middleware('auth:api');
    Route::post('currency/update/{id}', [CurrencyController::class, 'update'])->middleware('auth:api');
    Route::delete('currency/delete/{id}', [CurrencyController::class, 'destroy'])->middleware('auth:api');

    // FAQ
    Route::get('faqs', [FaqController::class, 'index']);
    Route::get('faq/{id}', [FaqController::class, 'show']);
    Route::post('faq/create', [FaqController::class, 'store'])->middleware('auth:api');
    Route::post('faq/update/{id}', [FaqController::class, 'update'])->middleware('auth:api');
    Route::delete('faq/delete/{id}', [FaqController::class, 'destroy'])->middleware('auth:api');

    // Menus
    Route::get('menus', [MenuController::class, 'index']);
    Route::get('menu/{id}', [MenuController::class, 'show']);
    Route::post('menu/create', [MenuController::class, 'store'])->middleware('auth:api');
    Route::post('menu/update/{id}', [MenuController::class, 'update'])->middleware('auth:api');
    Route::delete('menu/delete/{id}', [MenuController::class, 'destroy'])->middleware('auth:api');

    // Menu items
    Route::get('items/menu/{id}', [MenuItemController::class, 'index']); // By menu Id
    Route::get('item/{id}', [MenuItemController::class, 'show']); // By menu item Id
    Route::post('item/menu/create', [MenuItemController::class, 'store'])->middleware('auth:api');
    Route::post('item/menu/update/{id}', [MenuItemController::class, 'update'])->middleware('auth:api');
    Route::delete('item/menu/delete/{id}', [MenuItemController::class, 'destroy'])->middleware('auth:api');

    // Cart
    Route::get('cart/user/{id}', [CartController::class, 'show'])->middleware('auth:api');
    Route::post('cart/create', [CartController::class, 'store'])->middleware('auth:api');
    Route::delete('cart/delete/{id}', [CartController::class, 'destroy'])->middleware('auth:api');

    // Cart items
    Route::post('cart/item/create', [CartItemController::class, 'store'])->middleware('auth:api');
    Route::post('cart/item/update/{id}', [CartItemController::class, 'update'])->middleware('auth:api');
    Route::delete('cart/item/delete/{id}', [CartItemController::class, 'destroy'])->middleware('auth:api');

    // Orders
    Route::post('order/create', [OrderController::class, 'store'])->middleware('auth:api');
    Route::get('orders/all', [OrderController::class, 'index'])->middleware('auth:api');
    Route::get('order/{id}', [OrderController::class, 'show'])->middleware('auth:api');
    Route::get('orders/user/{id}', [OrderController::class, 'get_orders_by_user_id'])->middleware('auth:api');
    Route::post('order/update/{id}', [OrderController::class, 'update'])->middleware('auth:api');
    Route::post('order/cancel/{id}', [OrderController::class, 'cancel'])->middleware('auth:api');
    Route::delete('order/delete/{id}', [OrderController::class, 'destroy'])->middleware('auth:api');

    Route::post('orders/from-cart', [OrderController::class, 'createOrderFromCart'])->middleware('auth:api');

    // Order items
    Route::post('order/item/create', [OrderItemController::class, 'store'])->middleware('auth:api');

    // Email Templates//
    Route::post('email-template/create', [EmailTemplateController::class, 'store'])->middleware('auth:api');
    Route::post('email-template/update/{id}', [EmailTemplateController::class, 'update'])->middleware('auth:api');
    Route::get('email-templates', [EmailTemplateController::class, 'index'])->middleware('auth:api');
    Route::get('email-template/{id}', [EmailTemplateController::class, 'show'])->middleware('auth:api');
    Route::delete('email-template/delete/{id}', [EmailTemplateController::class, 'destroy'])->middleware('auth:api');

    //Plans
    Route::post('plans', [\App\Http\Controllers\PlansController::class, 'plans']);
    Route::post('plans/prepaid', [\App\Http\Controllers\PlansController::class, 'plan_prepaid']);
    Route::post('plans/postpaid', [\App\Http\Controllers\PlansController::class, 'plan_postpaid']);
    Route::post('plan/{id}', [\App\Http\Controllers\PlansController::class, 'plan_by_id']);  
    
});



Route::middleware('auth:sanctum')->prefix('eoglobal')->group(function (){
    //Plans
    Route::post('plans', [\App\Http\Controllers\PlansController::class, 'plans']);
    Route::post('plans/prepaid', [\App\Http\Controllers\PlansController::class, 'plan_prepaid']);
    Route::post('plans/postpaid', [\App\Http\Controllers\PlansController::class, 'plan_postpaid']);
    Route::post('plan/{id}', [\App\Http\Controllers\PlansController::class, 'plan_by_id']); 
});




