<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use App\User;

class CallBackController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //$this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index(Request $request)
    {
       return redirect("https://" . $request->input('shop') . "/admin/oauth/authorize?client_id=" 
                        . env('SHOPIFY_API_KEY') . "&scope=read_orders,write_products&redirect_uri=" . urlencode(env('APP_URL'))."/callback&grant_options[]=per-user");                
        
    }
    
    public function callback(Request $request)
    {
        $params = $request->all(); // Retrieve all request parameters
        $hmac = $request->input('hmac'); // Retrieve HMAC request parameter
        $params = array_diff_key($params, array('hmac' => '')); // Remove hmac from params
        ksort($params); // Sort params lexographically
        $computed_hmac = hash_hmac('sha256', http_build_query($params), env('SHOPIFY_SECRET_KEY'));
        
        // Use hmac data to check that the response is from Shopify or not
        if (hash_equals($hmac, $computed_hmac)) {
            $result = CallBackController::generateToken($params['code'],$params['shop']);
            $user = User::where('shopify_url','=', $params['shop'])->where('email','=', $result['associated_user']['email'])->first();
            $new = false;
            if(!$user){
                $user = new User();
                $user->name = $result['associated_user']['first_name'] . $result['associated_user']['last_name'];
                $user->email = $result['associated_user']['email'];
                $user->password = Hash::make('password');
                $user->shopify_url =  $params['shop'];
                $new = true;
            }
            $user->shopify_token = $result['access_token'];
            $user->save(); 
            // Login and "remember" the given user...
            Auth::login($user, true);
            if($new)
                return redirect("https://" . $user->shopify_url. '/admin/apps/schedule-app');
            else
                return view('home');
        }else{
            die('This request is NOT from Shopify!');
        }
    }
    
    public static function generateToken($code,$shop){
        $query = array(
        		"client_id" => env('SHOPIFY_API_KEY'), // Your API key
        		"client_secret" => env('SHOPIFY_SECRET_KEY'), // Your app credentials (secret key)
        		"code" => $code // Grab the access key from the URL
        );
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_URL, "https://" . $shop . "/admin/oauth/access_token");
        curl_setopt($ch, CURLOPT_POST, count($query));
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($query));
        $result = curl_exec($ch);
        curl_close($ch);
        $result = json_decode($result, true);
        return  $result;    
    }
}
